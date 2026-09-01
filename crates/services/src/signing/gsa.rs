//! GrandSlam (GSA) authentication against `gsa.apple.com`.
//!
//! Pure-Rust port of the protocol implemented by AltSign
//! (`ALTAppleAPI+Authentication`) and documented by the `grandslam`/`pypush`
//! projects: SRP-6a (SHA-256, RFC 5054 2048-bit group, no user name in `x`)
//! with Apple's `s2k`/`s2k_fo` password derivation, followed by the
//! `apptokens` exchange that yields the Xcode developer-services token.
//! Trusted-device two-factor authentication is supported through a
//! caller-provided prompt callback.

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{KeyInit, aead::AeadInPlace};
use base64::Engine;
use hmac::{Hmac, Mac};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info};
use zeroize::{Zeroize, Zeroizing};

use super::anisette::AnisetteData;
use super::srp::{SrpClient, SrpGroup, derive_srp_password};

const GSA_SERVICE: &str = "https://gsa.apple.com/grandslam/GsService2";
const GSA_VALIDATE: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
const GSA_VERIFY_TRUSTED: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
const GSA_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const XCODE_APP: &str = "com.apple.gs.xcode.auth";
const PROTOCOLS: [&str; 2] = ["s2k", "s2k_fo"];

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDecrypt = cbc::Decryptor<aes::Aes256>;
/// Apple uses a 16-byte GCM nonce for the encrypted app token.
type Aes256Gcm16 = aes_gcm::AesGcm<aes::Aes256, aes_gcm::aead::consts::U16>;

/// Asks the user for the six-digit trusted-device verification code.
pub type TwoFactorPrompt<'a> = &'a mut dyn FnMut() -> Result<String, GsaError>;

#[derive(Debug, Error)]
pub enum GsaError {
    #[error("GSA request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GSA response is not a valid property list: {0}")]
    Plist(#[from] plist::Error),
    #[error("GSA response is missing {0}")]
    MissingField(&'static str),
    #[error("GSA authentication failed ({ec}): {message}")]
    Apple { ec: i64, message: String },
    #[error("incorrect Apple ID or password")]
    InvalidCredentials,
    #[error("unsupported SRP protocol {0}")]
    UnsupportedProtocol(String),
    #[error("SRP safety check failed")]
    SrpSafety,
    #[error("server session proof (M2) does not match")]
    SessionProofMismatch,
    #[error("negotiated-protocol integrity check (np) does not match")]
    NegotiationProofMismatch,
    #[error("failed to decrypt the GSA response")]
    Decryption,
    #[error("the two-factor prompt did not supply a code")]
    TwoFactorCancelled,
    #[error("incorrect two-factor verification code")]
    InvalidVerificationCode,
    #[error("trusted-device two-factor verification failed ({ec}): {message}")]
    TwoFactor { ec: i64, message: String },
    #[error("account requires an unsupported two-factor method: {0}")]
    UnsupportedTwoFactor(String),
}

/// Authenticated developer-services session.
///
/// The values are credentials; they are never logged and are zeroized on
/// drop.
#[derive(Clone)]
pub struct DeveloperSession {
    dsid: Zeroizing<String>,
    auth_token: Zeroizing<String>,
}

impl std::fmt::Debug for DeveloperSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeveloperSession").finish_non_exhaustive()
    }
}

impl DeveloperSession {
    pub fn dsid(&self) -> &str {
        &self.dsid
    }

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }
}

/// GrandSlam authentication client.
pub struct GsaClient {
    http: reqwest::Client,
    anisette: AnisetteData,
}

impl GsaClient {
    pub fn new(anisette: AnisetteData) -> Self {
        Self {
            http: reqwest::Client::new(),
            anisette,
        }
    }

    /// Authenticate with an Apple ID, yielding a developer-services session.
    ///
    /// When the account requires trusted-device two-factor authentication, a
    /// verification prompt is pushed to the user's trusted devices and
    /// `two_factor` is called to collect the six-digit code. Credentials are
    /// used in memory only and never written to disk.
    pub async fn authenticate(
        &self,
        apple_id: &str,
        password: &str,
        two_factor: TwoFactorPrompt<'_>,
    ) -> Result<DeveloperSession, GsaError> {
        let mut two_factor = two_factor;
        let mut second_factor_done = false;
        loop {
            match self.authenticate_once(apple_id, password).await? {
                AuthOutcome::Session(session) => return Ok(session),
                AuthOutcome::RequiresTwoFactor { dsid, idms_token } => {
                    if second_factor_done {
                        return Err(GsaError::UnsupportedTwoFactor("trusted-device".to_owned()));
                    }
                    self.validate_trusted_device(&dsid, &idms_token, &mut two_factor)
                        .await?;
                    info!("two-factor verification accepted; retrying authentication");
                    second_factor_done = true;
                }
            }
        }
    }

    async fn authenticate_once(
        &self,
        apple_id: &str,
        password: &str,
    ) -> Result<AuthOutcome, GsaError> {
        // Protocol-negotiation integrity digest, chained as in
        // ALTAppleAPI+Authentication: "s2k" "," "s2k_fo" "|" ...
        let mut np_digest = Sha256::new();
        np_digest.update(PROTOCOLS[0].as_bytes());
        np_digest.update(b",");
        np_digest.update(PROTOCOLS[1].as_bytes());
        np_digest.update(b"|");

        let mut srp = SrpClient::<Sha256>::new(SrpGroup::rfc5054_2048(), apple_id);
        srp.set_no_username_in_x(true);
        let a = srp.public_value();

        let mut parameters = self.cpd();
        parameters.insert("A2k".into(), Value::Data(a));
        parameters.insert(
            "ps".into(),
            Value::Array(
                PROTOCOLS
                    .iter()
                    .map(|p| Value::String((*p).into()))
                    .collect(),
            ),
        );
        parameters.insert("u".into(), apple_id.into());
        parameters.insert("o".into(), "init".into());
        let response = self.post(&parameters).await?;

        let protocol = string(&response, "sp").ok_or(GsaError::MissingField("sp"))?;
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(GsaError::UnsupportedProtocol(protocol));
        }
        np_digest.update(b"|");
        np_digest.update(protocol.as_bytes());

        let salt = data(&response, "s").ok_or(GsaError::MissingField("s"))?;
        let server_public = data(&response, "B").ok_or(GsaError::MissingField("B"))?;
        let session_cookie = string(&response, "c").ok_or(GsaError::MissingField("c"))?;
        let iterations = integer(&response, "i").ok_or(GsaError::MissingField("i"))?;
        let iterations = u32::try_from(iterations).map_err(|_| GsaError::MissingField("i"))?;

        let mut password_key = derive_srp_password(password, &salt, iterations, &protocol);
        let m1 = srp
            .process_challenge(&salt, &server_public, &password_key)
            .map_err(|_| GsaError::SrpSafety)?;
        password_key.zeroize();

        let mut parameters = self.cpd();
        parameters.insert("c".into(), session_cookie.into());
        parameters.insert("M1".into(), Value::Data(m1));
        parameters.insert("u".into(), apple_id.into());
        parameters.insert("o".into(), "complete".into());
        let response = self.post(&parameters).await?;

        let m2 = data(&response, "M2").ok_or(GsaError::MissingField("M2"))?;
        srp.verify_session(&m2)
            .map_err(|_| GsaError::SessionProofMismatch)?;
        debug!("SRP session proof verified");

        np_digest.update(b"|");
        np_update_data(&mut np_digest, data(&response, "spd").as_deref());
        np_digest.update(b"|");
        np_update_data(&mut np_digest, data(&response, "sc").as_deref());
        np_digest.update(b"|");
        let np = data(&response, "np").ok_or(GsaError::MissingField("np"))?;
        let session_key = srp.session_key().ok_or(GsaError::SrpSafety)?;
        let hmac_key = hmac(session_key, b"HMAC key:");
        let expected_np = hmac(&hmac_key, &np_digest.finalize());
        if np != expected_np {
            return Err(GsaError::NegotiationProofMismatch);
        }

        let spd = data(&response, "spd").ok_or(GsaError::MissingField("spd"))?;
        let spd = decrypt_cbc(session_key, &spd)?;
        let spd = plist::from_bytes::<Dictionary>(&spd)?;
        let dsid = string(&spd, "adsid").ok_or(GsaError::MissingField("adsid"))?;
        let idms_token =
            string(&spd, "GsIdmsToken").ok_or(GsaError::MissingField("GsIdmsToken"))?;

        let auth_type = response
            .get("Status")
            .and_then(Value::as_dictionary)
            .and_then(|status| status.get("au"))
            .and_then(Value::as_string)
            .map(ToOwned::to_owned);
        if let Some(auth_type) = auth_type {
            if auth_type == "trustedDeviceSecondaryAuth" {
                debug!("trusted-device two-factor authentication required");
                return Ok(AuthOutcome::RequiresTwoFactor { dsid, idms_token });
            }
            return Err(GsaError::UnsupportedTwoFactor(auth_type));
        }

        let token = self.fetch_app_token(&dsid, &idms_token, &spd).await?;
        info!("GSA authentication succeeded");
        Ok(AuthOutcome::Session(DeveloperSession {
            dsid: Zeroizing::new(dsid),
            auth_token: Zeroizing::new(token),
        }))
    }

    /// Exchange the decrypted spd for the `com.apple.gs.xcode.auth` token.
    async fn fetch_app_token(
        &self,
        dsid: &str,
        idms_token: &str,
        spd: &Dictionary,
    ) -> Result<String, GsaError> {
        let sk = data(spd, "sk").ok_or(GsaError::MissingField("sk"))?;
        let cookie = data(spd, "c").ok_or(GsaError::MissingField("c"))?;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&sk).map_err(|_| GsaError::Decryption)?;
        mac.update(b"apptokens");
        mac.update(dsid.as_bytes());
        mac.update(XCODE_APP.as_bytes());
        let checksum = mac.finalize().into_bytes().to_vec();

        let mut parameters = self.cpd();
        parameters.insert("u".into(), dsid.into());
        parameters.insert("app".into(), Value::Array(vec![XCODE_APP.into()]));
        parameters.insert("c".into(), Value::Data(cookie));
        parameters.insert("t".into(), idms_token.into());
        parameters.insert("checksum".into(), Value::Data(checksum));
        parameters.insert("o".into(), "apptokens".into());
        let response = self.post(&parameters).await?;

        let encrypted = data(&response, "et").ok_or(GsaError::MissingField("et"))?;
        let decrypted = decrypt_token(&sk, &encrypted)?;
        let tokens = plist::from_bytes::<Dictionary>(&decrypted)?;
        let token = tokens
            .get("t")
            .and_then(Value::as_dictionary)
            .and_then(|apps| apps.get(XCODE_APP))
            .and_then(Value::as_dictionary)
            .and_then(|entry| entry.get("token"))
            .and_then(Value::as_string)
            .ok_or(GsaError::MissingField("token"))?;
        Ok(token.to_owned())
    }

    /// Push a verification prompt to trusted devices and submit the code.
    async fn validate_trusted_device(
        &self,
        dsid: &str,
        idms_token: &str,
        two_factor: &mut TwoFactorPrompt<'_>,
    ) -> Result<(), GsaError> {
        let request = self
            .http
            .get(GSA_VERIFY_TRUSTED)
            .headers(self.xcode_headers(dsid, idms_token));
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(GsaError::TwoFactor {
                ec: i64::from(response.status().as_u16()),
                message: "failed to trigger the trusted-device prompt".to_owned(),
            });
        }
        info!("a sign-in prompt was sent to the trusted devices");

        let code = two_factor()?;
        let code = Zeroizing::new(code);
        let request = self
            .http
            .get(GSA_VALIDATE)
            .headers(self.xcode_headers(dsid, idms_token))
            .header("security-code", code.as_str());
        let response = request.send().await?;
        let body: Dictionary = plist::from_bytes(&response.bytes().await?)?;
        let ec = integer(&body, "ec").unwrap_or(-1);
        match ec {
            0 => Ok(()),
            -21669 => Err(GsaError::InvalidVerificationCode),
            ec => Err(GsaError::TwoFactor {
                ec,
                message: string(&body, "em").unwrap_or_else(|| "unknown error".to_owned()),
            }),
        }
    }

    /// `cpd` client-data dictionary attached to every GrandSlam request.
    fn cpd(&self) -> Dictionary {
        let mut cpd = Dictionary::new();
        cpd.insert("bootstrap".into(), true.into());
        cpd.insert("icscrec".into(), true.into());
        cpd.insert("loc".into(), self.anisette.locale().into());
        cpd.insert("pbe".into(), false.into());
        cpd.insert("prkgen".into(), true.into());
        cpd.insert("svct".into(), "iCloud".into());
        cpd.insert(
            "X-Apple-I-Client-Time".into(),
            self.anisette.client_time().into(),
        );
        cpd.insert("X-Apple-Locale".into(), self.anisette.locale().into());
        cpd.insert(
            "X-Apple-I-TimeZone".into(),
            self.anisette.time_zone().into(),
        );
        cpd.insert(
            "X-Apple-I-MD".into(),
            self.anisette.one_time_password().into(),
        );
        cpd.insert(
            "X-Apple-I-MD-LU".into(),
            self.anisette.local_user_id().into(),
        );
        cpd.insert("X-Apple-I-MD-M".into(), self.anisette.machine_id().into());
        cpd.insert(
            "X-Apple-I-MD-RINFO".into(),
            self.anisette.routing_info().into(),
        );
        cpd.insert(
            "X-Mme-Device-Id".into(),
            self.anisette.device_unique_identifier().into(),
        );
        cpd.insert(
            "X-Apple-I-SRL-NO".into(),
            self.anisette.device_serial_number().into(),
        );
        cpd
    }

    async fn post(&self, parameters: &Dictionary) -> Result<Dictionary, GsaError> {
        let mut envelope = Dictionary::new();
        let mut header = Dictionary::new();
        header.insert("Version".into(), "1.0.1".into());
        envelope.insert("Header".into(), header.into());
        envelope.insert("Request".into(), parameters.clone().into());
        let mut body = Vec::new();
        Value::Dictionary(envelope).to_writer_xml(&mut body)?;
        let response = self
            .http
            .post(GSA_SERVICE)
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "*/*")
            .header("User-Agent", GSA_USER_AGENT)
            .header("X-MMe-Client-Info", self.anisette.device_description())
            .body(body)
            .send()
            .await?;
        let parsed: Dictionary = plist::from_bytes(&response.bytes().await?)?;
        let response = parsed
            .get("Response")
            .and_then(Value::as_dictionary)
            .ok_or(GsaError::MissingField("Response"))?;
        let status = response
            .get("Status")
            .and_then(Value::as_dictionary)
            .ok_or(GsaError::MissingField("Status"))?;
        let ec = integer(status, "ec").unwrap_or(0);
        if ec != 0 {
            let message = string(status, "em").unwrap_or_else(|| "unknown error".to_owned());
            return Err(match ec {
                -22406 => GsaError::InvalidCredentials,
                ec => GsaError::Apple { ec, message },
            });
        }
        Ok(response.clone())
    }

    /// Xcode-style headers used by the two-factor endpoints.
    fn xcode_headers(&self, dsid: &str, idms_token: &str) -> reqwest::header::HeaderMap {
        let identity_token =
            base64::engine::general_purpose::STANDARD.encode(format!("{dsid}:{idms_token}"));
        let mut headers = reqwest::header::HeaderMap::new();
        let mut insert = |name: &'static str, value: String| {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&value) {
                headers.insert(name, value);
            }
        };
        insert("Content-Type", "text/x-xml-plist".to_owned());
        insert("User-Agent", "Xcode".to_owned());
        insert("Accept", "text/x-xml-plist".to_owned());
        insert("Accept-Language", "en-us".to_owned());
        insert("X-Apple-App-Info", XCODE_APP.to_owned());
        insert("X-Xcode-Version", "11.2 (11B41)".to_owned());
        insert("X-Apple-Identity-Token", identity_token);
        insert("X-Apple-I-MD-M", self.anisette.machine_id().to_owned());
        insert("X-Apple-I-MD", self.anisette.one_time_password().to_owned());
        insert("X-Apple-I-MD-LU", self.anisette.local_user_id().to_owned());
        insert(
            "X-Apple-I-MD-RINFO",
            self.anisette.routing_info().to_string(),
        );
        insert(
            "X-Mme-Device-Id",
            self.anisette.device_unique_identifier().to_owned(),
        );
        insert(
            "X-MMe-Client-Info",
            self.anisette.device_description().to_owned(),
        );
        insert(
            "X-Apple-I-Client-Time",
            self.anisette.client_time().to_owned(),
        );
        insert("X-Apple-Locale", self.anisette.locale().to_owned());
        insert("X-Apple-I-TimeZone", self.anisette.time_zone().to_owned());
        headers
    }
}

enum AuthOutcome {
    Session(DeveloperSession),
    RequiresTwoFactor { dsid: String, idms_token: String },
}

/// Length-prefixed data update for the protocol-negotiation digest, matching
/// `ALTDigestUpdateData` (little-endian u32 length, then the bytes).
fn np_update_data(digest: &mut Sha256, data: Option<&[u8]>) {
    if let Some(data) = data {
        digest.update((data.len() as u32).to_le_bytes());
        digest.update(data);
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// AES-256-CBC with PKCS#7 padding; key and IV derived from the SRP session
/// key as in `ALTDecryptDataCBC`.
fn decrypt_cbc(session_key: &[u8], data: &[u8]) -> Result<Vec<u8>, GsaError> {
    let key = hmac(session_key, b"extra data key:");
    let iv = hmac(session_key, b"extra data iv:");
    let cipher =
        Aes256CbcDecrypt::new_from_slices(&key, &iv[..16]).map_err(|_| GsaError::Decryption)?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| GsaError::Decryption)
}

/// AES-256-GCM with a 16-byte nonce and the literal `XYZ` header as
/// associated data, as in `ALTDecryptDataGCM`.
fn decrypt_token(session_key: &[u8], data: &[u8]) -> Result<Vec<u8>, GsaError> {
    if data.len() < 35 || &data[..3] != b"XYZ" {
        return Err(GsaError::Decryption);
    }
    let cipher = Aes256Gcm16::new_from_slice(session_key).map_err(|_| GsaError::Decryption)?;
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(&data[3..19]);
    let mut buffer = data[19..data.len() - 16].to_vec();
    let tag = aes_gcm::Tag::from_slice(&data[data.len() - 16..]);
    cipher
        .decrypt_in_place_detached(nonce, b"XYZ", &mut buffer, tag)
        .map_err(|_| GsaError::Decryption)?;
    Ok(buffer)
}

fn string(dictionary: &Dictionary, key: &str) -> Option<String> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
}

fn data(dictionary: &Dictionary, key: &str) -> Option<Vec<u8>> {
    dictionary
        .get(key)
        .and_then(Value::as_data)
        .map(<[_]>::to_vec)
}

fn integer(dictionary: &Dictionary, key: &str) -> Option<i64> {
    let value = dictionary.get(key)?;
    value
        .as_signed_integer()
        .or_else(|| {
            value
                .as_unsigned_integer()
                .and_then(|v| i64::try_from(v).ok())
        })
        .or_else(|| value.as_string().and_then(|v| v.parse().ok()))
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockEncryptMut;

    use super::*;

    #[test]
    fn builds_grandslam_request_envelope() {
        let anisette = test_anisette();
        let client = GsaClient::new(anisette);
        let mut parameters = client.cpd();
        parameters.insert("u".into(), "user@example.com".into());
        parameters.insert("o".into(), "init".into());
        let mut envelope = Dictionary::new();
        let mut header = Dictionary::new();
        header.insert("Version".into(), "1.0.1".into());
        envelope.insert("Header".into(), header.into());
        envelope.insert("Request".into(), parameters.into());
        let mut body = Vec::new();
        Value::Dictionary(envelope)
            .to_writer_xml(&mut body)
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("<key>Header</key>"));
        assert!(text.contains("<key>Version</key>"));
        assert!(text.contains("<string>1.0.1</string>"));
        assert!(text.contains("<key>Request</key>"));
        assert!(text.contains("<key>svct</key>"));
        assert!(text.contains("<string>iCloud</string>"));
        assert!(text.contains("<key>X-Apple-I-MD-RINFO</key>"));
        assert!(text.contains("<integer>17106176</integer>"));
        assert!(text.contains("<key>bootstrap</key>"));
        assert!(text.contains("<true/>"));
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let session_key = [7u8; 32];
        let plaintext = b"hello grandslam session";
        let key = hmac(&session_key, b"extra data key:");
        let iv = hmac(&session_key, b"extra data iv:");
        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv[..16])
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let decrypted = decrypt_cbc(&session_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_token_roundtrip() {
        let session_key = [3u8; 32];
        let plaintext = b"token payload";
        let nonce_bytes = [9u8; 16];
        let cipher = Aes256Gcm16::new_from_slice(&session_key).unwrap();
        let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(&nonce_bytes);
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"XYZ", &mut buffer)
            .unwrap();
        let mut packaged = b"XYZ".to_vec();
        packaged.extend_from_slice(&nonce_bytes);
        packaged.extend_from_slice(&buffer);
        packaged.extend_from_slice(&tag);
        let decrypted = decrypt_token(&session_key, &packaged).unwrap();
        assert_eq!(decrypted, plaintext);
        buffer[0] ^= 1;
        assert!(decrypt_token(&session_key, b"bad").is_err());
    }

    fn test_anisette() -> AnisetteData {
        AnisetteData::for_test()
    }
}
