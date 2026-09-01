//! Apple Developer Services API (`developerservices2.apple.com`).
//!
//! Pure-Rust port of AltSign's `ALTAppleAPI`: Xcode-style QH65B2 plist
//! requests authenticated with a GSA session and anisette headers. Covers
//! team listing, device registration, development-certificate CSR
//! submission, App ID registration, and team provisioning-profile download.

use base64::Engine;
use plist::{Dictionary, Value};
use rsa::pkcs8::EncodePrivateKey;
use thiserror::Error;
use tracing::{debug, info};
use x509_cert::der::EncodePem;

use super::anisette::AnisetteData;
use super::gsa::DeveloperSession;

const BASE_URL: &str = "https://developerservices2.apple.com/services/QH65B2";
const SERVICES_URL: &str = "https://developerservices2.apple.com/services/v1";
const PROTOCOL_VERSION: &str = "QH65B2";
const CLIENT_ID: &str = "XABBG36SBA";

#[derive(Debug, Error)]
pub enum DeveloperApiError {
    #[error("developer services request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("developer services response is not valid: {0}")]
    Plist(#[from] plist::Error),
    #[error("developer services response is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("developer services response is missing {0}")]
    MissingField(&'static str),
    #[error("developer services error ({code}): {message}")]
    Apple { code: i64, message: String },
    #[error("the account has no developer teams")]
    NoTeams,
    #[error("the device is already registered")]
    DeviceAlreadyRegistered,
    #[error("the App ID limit for the account was reached")]
    AppIdLimitReached,
    #[error("the bundle identifier is not available: {0}")]
    BundleIdentifierUnavailable(String),
    #[error("failed to generate the certificate request: {0}")]
    CertificateRequest(String),
    #[error("no iOS development certificate could be issued")]
    CertificateLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Team {
    identifier: String,
    name: String,
    kind: String,
}

impl Team {
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Team kind, e.g. `"free"` or `"Company/Organization"`.
    pub fn kind(&self) -> &str {
        &self.kind
    }
}

/// An Apple-issued development certificate plus its private key.
///
/// The private key is generated locally for the CSR and never leaves the
/// host; both values are credentials and are never logged.
pub struct DevelopmentCertificate {
    /// PEM-encoded X.509 certificate returned by Apple.
    certificate_pem: Vec<u8>,
    /// PKCS#8 DER private key matching the CSR.
    private_key_der: Vec<u8>,
}

impl DevelopmentCertificate {
    pub fn certificate_pem(&self) -> &[u8] {
        &self.certificate_pem
    }

    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}

/// A downloaded provisioning profile (CMS-signed `.mobileprovision` data).
#[derive(Clone)]
pub struct ProvisioningProfile {
    identifier: String,
    data: Vec<u8>,
}

impl std::fmt::Debug for ProvisioningProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningProfile")
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

impl ProvisioningProfile {
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

pub struct DeveloperClient {
    http: reqwest::Client,
    session: DeveloperSession,
    anisette: AnisetteData,
}

impl DeveloperClient {
    pub fn new(session: DeveloperSession, anisette: AnisetteData) -> Self {
        Self {
            http: reqwest::Client::new(),
            session,
            anisette,
        }
    }

    /// `listTeams.action`
    pub async fn list_teams(&self) -> Result<Vec<Team>, DeveloperApiError> {
        let response = self.request("listTeams.action", None, &[]).await?;
        let teams = response
            .get("teams")
            .and_then(Value::as_array)
            .ok_or(DeveloperApiError::MissingField("teams"))?;
        let teams = teams
            .iter()
            .filter_map(|entry| {
                let entry = entry.as_dictionary()?;
                Some(Team {
                    identifier: string(entry, "teamId")?,
                    name: string(entry, "name").unwrap_or_default(),
                    kind: string(entry, "type").unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        if teams.is_empty() {
            return Err(DeveloperApiError::NoTeams);
        }
        Ok(teams)
    }

    /// `ios/addDevice.action`; already-registered devices are reported as
    /// `Ok(false)`.
    pub async fn register_device(
        &self,
        team: &Team,
        udid: &str,
        name: &str,
    ) -> Result<bool, DeveloperApiError> {
        let parameters = [
            ("deviceNumber", Value::from(udid)),
            ("name", Value::from(name)),
        ];
        match self
            .request("ios/addDevice.action", Some(team), &parameters)
            .await
        {
            Ok(_) => {
                info!("registered device with the developer account");
                Ok(true)
            }
            Err(DeveloperApiError::Apple { code: 35, message }) => {
                if message.to_lowercase().contains("already exists") {
                    debug!("device already registered with the developer account");
                    Ok(false)
                } else {
                    Err(DeveloperApiError::Apple { code: 35, message })
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Submit a fresh development CSR (`ios/submitDevelopmentCSR.action`).
    pub async fn add_certificate(
        &self,
        team: &Team,
        machine_name: &str,
    ) -> Result<DevelopmentCertificate, DeveloperApiError> {
        let (csr_pem, private_key_der) = generate_csr()?;
        let parameters = [
            ("csrContent", Value::from(csr_pem)),
            ("machineId", Value::from(uuid::Uuid::new_v4().to_string())),
            ("machineName", Value::from(machine_name)),
        ];
        let response = self
            .request("ios/submitDevelopmentCSR.action", Some(team), &parameters)
            .await?;
        let request = response
            .get("certRequest")
            .and_then(Value::as_dictionary)
            .ok_or(DeveloperApiError::MissingField("certRequest"))?;
        let certificate = data(request, "certContent")
            .or_else(|| {
                string(request, "certificateContent").and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .ok()
                })
            })
            .ok_or(DeveloperApiError::MissingField("certContent"))?;
        let certificate_pem = pem_encode("CERTIFICATE", &certificate);
        info!("issued a new iOS development certificate");
        Ok(DevelopmentCertificate {
            certificate_pem,
            private_key_der,
        })
    }

    /// List iOS development certificates (`services/v1/certificates`).
    pub async fn list_certificates(&self, team: &Team) -> Result<Vec<String>, DeveloperApiError> {
        let response = self
            .services_request(
                "certificates",
                "GET",
                team,
                &[("filter[certificateType]", "IOS_DEVELOPMENT")],
            )
            .await?;
        let identifiers = response
            .get("data")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .as_dictionary()?
                            .get("id")?
                            .as_string()
                            .map(str::to_owned)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(identifiers)
    }

    /// Revoke a certificate (`DELETE services/v1/certificates/<id>`).
    pub async fn revoke_certificate(
        &self,
        team: &Team,
        identifier: &str,
    ) -> Result<(), DeveloperApiError> {
        self.services_request(&format!("certificates/{identifier}"), "DELETE", team, &[])
            .await?;
        info!("revoked an existing iOS development certificate");
        Ok(())
    }

    /// `ios/listAppIds.action`; returns `(identifier, bundle_id)` pairs.
    pub async fn list_app_ids(
        &self,
        team: &Team,
    ) -> Result<Vec<(String, String)>, DeveloperApiError> {
        let response = self
            .request("ios/listAppIds.action", Some(team), &[])
            .await?;
        let app_ids = response
            .get("appIds")
            .and_then(Value::as_array)
            .ok_or(DeveloperApiError::MissingField("appIds"))?;
        Ok(app_ids
            .iter()
            .filter_map(|entry| {
                let entry = entry.as_dictionary()?;
                Some((string(entry, "appIdId")?, string(entry, "identifier")?))
            })
            .collect())
    }

    /// `ios/addAppId.action`; returns the new App ID identifier.
    pub async fn add_app_id(
        &self,
        team: &Team,
        bundle_id: &str,
        name: &str,
    ) -> Result<String, DeveloperApiError> {
        // Apple's console sanitizes names to alphanumerics and spaces.
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == ' ' {
                    c
                } else {
                    ' '
                }
            })
            .collect();
        let parameters = [
            ("identifier", Value::from(bundle_id)),
            ("name", Value::from(name)),
        ];
        let response = match self
            .request("ios/addAppId.action", Some(team), &parameters)
            .await
        {
            Ok(response) => response,
            Err(DeveloperApiError::Apple { code, message }) => {
                return Err(match code {
                    9120 => DeveloperApiError::AppIdLimitReached,
                    9401 => DeveloperApiError::BundleIdentifierUnavailable(bundle_id.into()),
                    _ => DeveloperApiError::Apple { code, message },
                });
            }
            Err(error) => return Err(error),
        };
        let app_id = response
            .get("appId")
            .and_then(Value::as_dictionary)
            .and_then(|app_id| string(app_id, "appIdId"))
            .ok_or(DeveloperApiError::MissingField("appId"))?;
        info!(bundle_id, "registered App ID");
        Ok(app_id)
    }

    /// `ios/downloadTeamProvisioningProfile.action`.
    pub async fn download_team_provisioning_profile(
        &self,
        team: &Team,
        app_id: &str,
    ) -> Result<ProvisioningProfile, DeveloperApiError> {
        let parameters = [("appIdId", Value::from(app_id))];
        let response = self
            .request(
                "ios/downloadTeamProvisioningProfile.action",
                Some(team),
                &parameters,
            )
            .await?;
        let profile = response
            .get("provisioningProfile")
            .and_then(Value::as_dictionary)
            .ok_or(DeveloperApiError::MissingField("provisioningProfile"))?;
        let identifier =
            string(profile, "provisioningProfileId").unwrap_or_else(|| app_id.to_owned());
        let encoded = data(profile, "encodedProfile")
            .ok_or(DeveloperApiError::MissingField("encodedProfile"))?;
        info!("downloaded the team provisioning profile");
        Ok(ProvisioningProfile {
            identifier,
            data: encoded,
        })
    }

    /// QH65B2 plist request (`sendRequestWithURL` in AltSign).
    async fn request(
        &self,
        action: &str,
        team: Option<&Team>,
        extra: &[(&str, Value)],
    ) -> Result<Dictionary, DeveloperApiError> {
        let mut parameters = Dictionary::new();
        parameters.insert("clientId".into(), CLIENT_ID.into());
        parameters.insert("protocolVersion".into(), PROTOCOL_VERSION.into());
        parameters.insert(
            "requestId".into(),
            uuid::Uuid::new_v4().to_string().to_uppercase().into(),
        );
        if let Some(team) = team {
            parameters.insert("teamId".into(), team.identifier().into());
        }
        for (key, value) in extra {
            parameters.insert((*key).into(), value.clone());
        }
        let mut body = Vec::new();
        Value::Dictionary(parameters).to_writer_xml(&mut body)?;
        let url = format!("{BASE_URL}/{action}?clientId={CLIENT_ID}");
        let response = self
            .http
            .post(&url)
            .headers(self.headers("text/x-xml-plist"))
            .body(body)
            .send()
            .await?;
        let parsed: Dictionary = plist::from_bytes(&response.bytes().await?)?;
        check_result_code(&parsed)?;
        Ok(parsed)
    }

    /// `services/v1` JSON request with method override
    /// (`sendServicesRequest` in AltSign).
    async fn services_request(
        &self,
        path: &str,
        method: &str,
        team: &Team,
        query: &[(&str, &str)],
    ) -> Result<Dictionary, DeveloperApiError> {
        let mut pairs = vec![("teamId", team.identifier())];
        pairs.extend(query.iter().copied());
        let query_string = reqwest::Url::parse_with_params("https://localhost/", &pairs)
            .map_err(|_| DeveloperApiError::MissingField("query params"))?
            .query()
            .unwrap_or_default()
            .to_owned();
        let body = serde_json::json!({ "urlEncodedQueryParams": query_string }).to_string();
        let url = format!("{SERVICES_URL}/{path}");
        let response = self
            .http
            .post(&url)
            .headers(self.headers("application/vnd.api+json"))
            .header("X-HTTP-Method-Override", method)
            .body(body)
            .send()
            .await?;
        let bytes = response.bytes().await?;
        if bytes.is_empty() {
            return Ok(Dictionary::new());
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)?;
        let dictionary = match parsed {
            serde_json::Value::Object(map) => map
                .into_iter()
                .map(|(key, value)| (key, json_to_plist(value)))
                .collect(),
            _ => return Err(DeveloperApiError::MissingField("root object")),
        };
        check_result_code(&dictionary)?;
        Ok(dictionary)
    }

    fn headers(&self, content_type: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut insert = |name: &'static str, value: String| {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&value) {
                headers.insert(name, value);
            }
        };
        insert("Content-Type", content_type.to_owned());
        insert("Accept", content_type.to_owned());
        insert("Accept-Language", "en-us".to_owned());
        insert("User-Agent", "Xcode".to_owned());
        insert("X-Apple-App-Info", "com.apple.gs.xcode.auth".to_owned());
        insert("X-Xcode-Version", "11.2 (11B41)".to_owned());
        insert("X-Apple-I-Identity-Id", self.session.dsid().to_owned());
        insert("X-Apple-GS-Token", self.session.auth_token().to_owned());
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
        insert("X-Apple-I-Locale", self.anisette.locale().to_owned());
        insert("X-Apple-I-TimeZone", self.anisette.time_zone().to_owned());
        headers
    }
}

fn check_result_code(response: &Dictionary) -> Result<(), DeveloperApiError> {
    let code = match response.get("resultCode") {
        Some(value) => value
            .as_signed_integer()
            .or_else(|| value.as_string().and_then(|text| text.parse().ok()))
            .ok_or(DeveloperApiError::MissingField("resultCode"))?,
        None => return Ok(()),
    };
    if code == 0 {
        return Ok(());
    }
    let message = string(response, "userString")
        .or_else(|| string(response, "resultString"))
        .unwrap_or_else(|| "unknown error".to_owned());
    Err(DeveloperApiError::Apple { code, message })
}

fn json_to_plist(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::String(String::new()),
        serde_json::Value::Bool(v) => Value::Boolean(v),
        serde_json::Value::Number(v) => v
            .as_i64()
            .map_or_else(|| Value::from(v.as_f64().unwrap_or_default()), Value::from),
        serde_json::Value::String(v) => Value::String(v),
        serde_json::Value::Array(v) => Value::Array(v.into_iter().map(json_to_plist).collect()),
        serde_json::Value::Object(v) => Value::Dictionary(
            v.into_iter()
                .map(|(key, value)| (key, json_to_plist(value)))
                .collect(),
        ),
    }
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

fn pem_encode(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem.into_bytes()
}

/// Generate an RSA-2048 key pair and a SHA-1-signed CSR, matching AltSign's
/// `ALTCertificateRequest` (Apple accepts SHA-1 CSRs for development certs).
fn generate_csr() -> Result<(String, Vec<u8>), DeveloperApiError> {
    use rsa::pkcs1v15::SigningKey;
    use sha1::Sha1;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::name::Name;

    let mut rng = rand::thread_rng();
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| DeveloperApiError::CertificateRequest(e.to_string()))?;
    let subject: Name = "C=US,ST=CA,L=Los Angeles,O=AltSign,CN=AltSign"
        .parse()
        .map_err(|e| DeveloperApiError::CertificateRequest(format!("{e:?}")))?;
    let signing_key = SigningKey::<Sha1>::new(key.clone());
    let builder = RequestBuilder::new(subject, &signing_key)
        .map_err(|e| DeveloperApiError::CertificateRequest(e.to_string()))?;
    let csr = builder
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|e| DeveloperApiError::CertificateRequest(e.to_string()))?;
    let csr_pem = csr
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|e| DeveloperApiError::CertificateRequest(e.to_string()))?;
    let private_key_der = key
        .to_pkcs8_der()
        .map_err(|e| DeveloperApiError::CertificateRequest(e.to_string()))?
        .as_bytes()
        .to_vec();
    Ok((csr_pem, private_key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_has_expected_subject_and_parses() {
        let (csr_pem, private_key_der) = generate_csr().expect("CSR generation");
        assert!(csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let (label, document) = x509_cert::der::Document::from_pem(&csr_pem).expect("CSR PEM");
        assert_eq!(label, "CERTIFICATE REQUEST");
        let csr = x509_cert::request::CertReq::from_der(document.as_bytes()).expect("CSR DER");
        let subject = csr.info.subject.to_string();
        assert!(subject.contains("CN=AltSign"), "subject: {subject}");
        assert!(subject.contains("C=US"), "subject: {subject}");
        assert!(!private_key_der.is_empty());
        rsa::RsaPrivateKey::from_pkcs8_der(&private_key_der).expect("PKCS#8 private key");
        use rsa::pkcs8::DecodePrivateKey;
        use x509_cert::der::Decode;
    }

    #[test]
    fn maps_apple_result_codes() {
        let mut response = Dictionary::new();
        response.insert("resultCode".into(), 0.into());
        assert!(check_result_code(&response).is_ok());
        response.insert("resultCode".into(), 9401.into());
        response.insert("userString".into(), "taken".into());
        assert!(matches!(
            check_result_code(&response),
            Err(DeveloperApiError::Apple { code: 9401, .. })
        ));
    }

    #[test]
    fn pem_wraps_der_at_64_columns() {
        let pem = pem_encode("CERTIFICATE", &[1u8; 100]);
        let text = String::from_utf8(pem).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        assert!(
            text.lines()
                .skip(1)
                .take_while(|l| !l.starts_with('-'))
                .all(|l| l.len() <= 64)
        );
    }
}
