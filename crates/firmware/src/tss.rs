use std::io::Cursor;

use legacy_ios_core::Ecid;
use plist::{Dictionary, Value};
use reqwest::Url;
use thiserror::Error;
use tracing::{debug, info};

use crate::BuildIdentity;

const DEFAULT_TSS_ENDPOINT: &str = "https://gs.apple.com/TSS/controller?action=2";
const TSS_VERSION: &str = "libauthinstall-1033.0.2";

#[derive(Clone, Debug)]
pub struct TssRequest {
    dictionary: Dictionary,
}

impl TssRequest {
    pub fn new() -> Self {
        let mut dictionary = Dictionary::new();
        dictionary.insert("@HostPlatformInfo".into(), "mac".into());
        dictionary.insert("@VersionInfo".into(), TSS_VERSION.into());
        dictionary.insert(
            "@UUID".into(),
            uuid::Uuid::new_v4().to_string().to_uppercase().into(),
        );
        Self { dictionary }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.dictionary.insert(key.into(), value.into());
    }

    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    pub fn for_build_identity(identity: &BuildIdentity, parameters: &ApParameters) -> Self {
        let mut request = Self::new();
        request.insert("@APTicket", true);
        request.insert("@ApImg4Ticket", parameters.supports_img4);
        request.insert("ApBoardID", parameters.board_id);
        request.insert("ApChipID", parameters.chip_id);
        request.insert("ApECID", parameters.ecid.get());
        request.insert("ApProductionMode", parameters.production_mode);
        request.insert("ApSecurityDomain", parameters.security_domain);
        request.insert("ApSecurityMode", parameters.security_mode);
        request.insert("ApSupportsImg4", parameters.supports_img4);
        request.insert("UID_MODE", false);
        if let Some(nonce) = &parameters.ap_nonce {
            request.insert("ApNonce", Value::Data(nonce.clone()));
        }
        if let Some(nonce) = &parameters.sep_nonce {
            request.insert("SepNonce", Value::Data(nonce.clone()));
        }

        let condition_parameters = parameters.rule_dictionary();
        for (name, value) in identity.manifest() {
            let Some(component) = value.as_dictionary() else {
                continue;
            };
            if component.get("Trusted").and_then(Value::as_boolean) == Some(false) {
                continue;
            }
            let mut entry = component.clone();
            let info = entry.remove("Info").and_then(Value::into_dictionary);
            if let Some(rules) = info
                .as_ref()
                .and_then(|info| info.get("RestoreRequestRules"))
                .and_then(Value::as_array)
            {
                apply_restore_request_rules(&mut entry, &condition_parameters, rules);
            }
            if !entry.contains_key("Digest") {
                entry.insert("Digest".into(), Value::Data(Vec::new()));
            }
            request.insert(name, entry);
        }
        request
    }

    pub fn for_baseband(
        identity: &BuildIdentity,
        parameters: &BasebandParameters,
    ) -> Result<Self, TssError> {
        let mut request = Self::new();
        request.insert("@APTicket", false);
        request.insert("@ApImg4Ticket", false);
        request.insert("@BBTicket", true);
        request.insert("ApECID", parameters.ecid.get());
        request.insert("BbChipID", parameters.chip_id);
        request.insert("BbGoldCertId", parameters.gold_cert_id);
        request.insert("BbSNUM", Value::Data(parameters.serial_number.clone()));
        if let Some(nonce) = &parameters.nonce {
            request.insert("BbNonce", Value::Data(nonce.clone()));
        }

        for key in [
            "UniqueBuildID",
            "BbProvisioningManifestKeyHash",
            "BbActivationManifestKeyHash",
            "BbCalibrationManifestKeyHash",
            "BbFactoryActivationManifestKeyHash",
            "BbFDRSecurityKeyHash",
            "BbSkeyId",
        ] {
            if let Some(value) = identity.raw().get(key) {
                request.insert(key, value.clone());
            }
        }
        for key in ["ApChipID", "ApBoardID", "ApSecurityDomain"] {
            if let Some(value) = identity.raw().get(key).and_then(plist_integer) {
                request.insert(key, value);
            }
        }

        let mut baseband = identity
            .manifest()
            .get("BasebandFirmware")
            .and_then(Value::as_dictionary)
            .cloned()
            .ok_or(TssError::MissingBasebandManifest)?;
        baseband.remove("Info");
        request.insert("BasebandFirmware", baseband);
        if identity
            .raw()
            .get("Info")
            .and_then(Value::as_dictionary)
            .and_then(|info| info.get("FDRSupport"))
            .and_then(Value::as_boolean)
            == Some(true)
        {
            request.insert("ApProductionMode", true);
            request.insert("ApSecurityMode", true);
        }
        Ok(request)
    }

    /// Build a Cryptex1 / Cryptex1LocalPolicy TSS request from the merged
    /// request parameters (tsschecker `tss_request_add_cryptex_tags`,
    /// tss.c:1420-1453). The `Ap,LocalPolicy` parameter selects the
    /// local-policy branch.
    pub fn for_cryptex(parameters: &Dictionary) -> Result<Self, TssError> {
        let mut request = Self::new();
        // tss_request_add_common_tags (tss.c:347-361).
        for key in [
            "ApECID",
            "UniqueBuildID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
        ] {
            if let Some(value) = parameters.get(key) {
                request.insert(key, value.clone());
            }
        }
        if parameters.contains_key("Ap,LocalPolicy") {
            // Cryptex1LocalPolicy: tss_request_add_local_policy_tags
            // (tss.c:86-128) plus Ap,NextStageCryptex1IM4MHash.
            request.insert("@ApImg4Ticket", true);
            for key in ["Ap,LocalBoot", "Ap,LocalPolicy", "Ap,NextStageIM4MHash"] {
                let value = parameters
                    .get(key)
                    .ok_or(TssError::MissingCryptexParameter(key))?;
                request.insert(key, value.clone());
            }
            for key in [
                "Ap,RecoveryOSPolicyNonceHash",
                "Ap,VolumeUUID",
                "ApECID",
                "ApChipID",
                "ApBoardID",
                "ApSecurityDomain",
                "ApNonce",
            ] {
                if let Some(value) = parameters.get(key) {
                    request.insert(key, value.clone());
                }
            }
            for key in ["ApSecurityMode", "ApProductionMode"] {
                if !request.dictionary.contains_key(key) {
                    let value = parameters
                        .get(key)
                        .ok_or(TssError::MissingCryptexParameter(key))?;
                    request.insert(key, value.clone());
                }
            }
            if let Some(value) = parameters.get("Ap,NextStageCryptex1IM4MHash") {
                request.insert("Ap,NextStageCryptex1IM4MHash", value.clone());
            }
        } else {
            // Cryptex1 ticket request.
            request.insert("@Cryptex1,Ticket", true);
            for key in ["ApSecurityMode", "ApProductionMode"] {
                if let Some(value) = parameters.get(key) {
                    request.insert(key, value.clone());
                }
            }
            for (key, value) in parameters {
                if key.starts_with("Cryptex1") {
                    request.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(request)
    }
}

impl Default for TssRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApParameters {
    pub board_id: u64,
    pub chip_id: u64,
    pub ecid: Ecid,
    pub ap_nonce: Option<Vec<u8>>,
    pub sep_nonce: Option<Vec<u8>>,
    pub production_mode: bool,
    pub security_domain: u64,
    pub security_mode: bool,
    pub supports_img4: bool,
    pub in_rom_dfu: bool,
}

impl ApParameters {
    pub fn new(board_id: u64, chip_id: u64, ecid: Ecid) -> Self {
        Self {
            board_id,
            chip_id,
            ecid,
            ap_nonce: None,
            sep_nonce: None,
            production_mode: true,
            security_domain: 1,
            security_mode: true,
            supports_img4: true,
            in_rom_dfu: false,
        }
    }

    fn rule_dictionary(&self) -> Dictionary {
        let mut parameters = Dictionary::new();
        parameters.insert("ApProductionMode".into(), self.production_mode.into());
        parameters.insert("ApSecurityMode".into(), self.security_mode.into());
        parameters.insert("ApSupportsImg4".into(), self.supports_img4.into());
        parameters.insert("ApInRomDFU".into(), self.in_rom_dfu.into());
        parameters
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasebandParameters {
    pub ecid: Ecid,
    pub chip_id: u64,
    pub gold_cert_id: u64,
    pub serial_number: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
}

impl BasebandParameters {
    pub fn new(ecid: Ecid, chip_id: u64, gold_cert_id: u64, serial_number: Vec<u8>) -> Self {
        Self {
            ecid,
            chip_id,
            gold_cert_id,
            serial_number,
            nonce: None,
        }
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

#[derive(Clone, Debug)]
pub struct TssResponse {
    dictionary: Dictionary,
}

impl TssResponse {
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    pub fn into_dictionary(self) -> Dictionary {
        self.dictionary
    }
}

#[derive(Clone, Debug)]
pub struct TssClient {
    endpoint: Url,
    client: reqwest::Client,
}

impl TssClient {
    pub fn new() -> Self {
        Self {
            endpoint: Url::parse(DEFAULT_TSS_ENDPOINT).expect("default TSS endpoint must be valid"),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_endpoint(endpoint: Url) -> Self {
        Self {
            endpoint,
            client: reqwest::Client::new(),
        }
    }

    pub fn with_endpoint_str(endpoint: &str) -> Result<Self, TssError> {
        let endpoint =
            Url::parse(endpoint).map_err(|_| TssError::InvalidEndpoint(endpoint.to_owned()))?;
        Ok(Self::with_endpoint(endpoint))
    }

    pub async fn send(&self, request: &TssRequest) -> Result<TssResponse, TssError> {
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, request.dictionary())?;
        debug!(
            keys = request.dictionary().len(),
            "sending redacted TSS request"
        );
        let response = self
            .client
            .post(self.endpoint.clone())
            .header("Cache-Control", "no-cache")
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("User-Agent", "InetURL/1.0")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let response = parse_response(&response)?;
        info!(
            keys = response.dictionary.len(),
            "received successful TSS response"
        );
        Ok(response)
    }
}

impl Default for TssClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn apply_restore_request_rules(
    input: &mut Dictionary,
    parameters: &Dictionary,
    rules: &[Value],
) {
    for rule in rules {
        let Some(rule) = rule.as_dictionary() else {
            continue;
        };
        let Some(conditions) = rule.get("Conditions").and_then(Value::as_dictionary) else {
            continue;
        };
        let matches = conditions.iter().all(|(key, expected)| {
            condition_parameter(key)
                .and_then(|parameter| parameters.get(parameter))
                .is_some_and(|actual| actual == expected)
        });
        if !matches {
            continue;
        }
        let Some(actions) = rule.get("Actions").and_then(Value::as_dictionary) else {
            continue;
        };
        for (key, value) in actions {
            if value.as_unsigned_integer() == Some(255) || value.as_signed_integer() == Some(255) {
                continue;
            }
            input.insert(key.clone(), value.clone());
        }
    }
}

fn condition_parameter(condition: &str) -> Option<&'static str> {
    match condition {
        "ApRawProductionMode" | "ApCurrentProductionMode" => Some("ApProductionMode"),
        "ApRawSecurityMode" => Some("ApSecurityMode"),
        "ApRequiresImage4" => Some("ApSupportsImg4"),
        "ApDemotionPolicyOverride" => Some("DemotionPolicy"),
        "ApInRomDFU" => Some("ApInRomDFU"),
        _ => None,
    }
}

fn plist_integer(value: &Value) -> Option<u64> {
    value.as_unsigned_integer().or_else(|| {
        let value = value.as_string()?;
        u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
    })
}

fn parse_response(response: &str) -> Result<TssResponse, TssError> {
    let response = response.trim();
    if !response.starts_with("STATUS=0&MESSAGE=SUCCESS") {
        let message = response
            .split('&')
            .find_map(|value| value.strip_prefix("MESSAGE="))
            .unwrap_or("unknown TSS error");
        return Err(TssError::Rejected(message.to_owned()));
    }
    let payload = response
        .split_once("REQUEST_STRING=")
        .map(|(_, payload)| payload)
        .ok_or(TssError::MissingPayload)?;
    let value = Value::from_reader(Cursor::new(payload.as_bytes()))?;
    let dictionary = value
        .into_dictionary()
        .ok_or(TssError::PayloadNotDictionary)?;
    Ok(TssResponse { dictionary })
}

#[derive(Debug, Error)]
pub enum TssError {
    #[error("TSS HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TSS plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("TSS rejected the request: {0}")]
    Rejected(String),
    #[error("TSS response did not include REQUEST_STRING")]
    MissingPayload,
    #[error("TSS payload is not a dictionary")]
    PayloadNotDictionary,
    #[error("invalid TSS endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("BuildIdentity has no BasebandFirmware manifest")]
    MissingBasebandManifest,
    #[error("cryptex TSS parameters are missing {0}")]
    MissingCryptexParameter(&'static str),
}

#[cfg(test)]
mod tests {
    use legacy_ios_core::BoardConfig;

    use super::*;
    use crate::{BuildManifest, RestoreBehavior};

    #[test]
    fn builds_cryptex1_ticket_request() {
        let mut parameters = Dictionary::new();
        parameters.insert("ApECID".into(), 42_u64.into());
        parameters.insert("ApChipID".into(), 0x8020_u64.into());
        parameters.insert("ApBoardID".into(), 0x0c_u64.into());
        parameters.insert("ApSecurityMode".into(), true.into());
        parameters.insert("ApProductionMode".into(), true.into());
        parameters.insert("Cryptex1,ChipID".into(), 0x8020_u64.into());
        parameters.insert("Cryptex1,Nonce".into(), Value::Data(vec![1, 2]));
        parameters.insert("Unrelated".into(), "ignored".into());

        let request = TssRequest::for_cryptex(&parameters).unwrap();
        let dictionary = request.dictionary();

        assert_eq!(
            dictionary
                .get("@Cryptex1,Ticket")
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert!(!dictionary.contains_key("@ApImg4Ticket"));
        assert_eq!(
            dictionary
                .get("ApECID")
                .and_then(Value::as_unsigned_integer),
            Some(42)
        );
        assert_eq!(
            dictionary
                .get("Cryptex1,ChipID")
                .and_then(Value::as_unsigned_integer),
            Some(0x8020)
        );
        assert_eq!(
            dictionary.get("Cryptex1,Nonce").and_then(Value::as_data),
            Some([1, 2].as_slice())
        );
        // Only Cryptex1-prefixed parameters are copied beyond the common tags.
        assert!(!dictionary.contains_key("Unrelated"));
    }

    #[test]
    fn builds_cryptex1_local_policy_request() {
        let mut parameters = Dictionary::new();
        parameters.insert("ApECID".into(), 42_u64.into());
        parameters.insert("Ap,LocalBoot".into(), false.into());
        parameters.insert("Ap,LocalPolicy".into(), Value::Data(vec![3, 4]));
        parameters.insert("Ap,NextStageIM4MHash".into(), Value::Data(vec![5, 6]));
        parameters.insert(
            "Ap,NextStageCryptex1IM4MHash".into(),
            Value::Data(vec![7, 8]),
        );
        parameters.insert("ApSecurityMode".into(), true.into());
        parameters.insert("ApProductionMode".into(), true.into());

        let request = TssRequest::for_cryptex(&parameters).unwrap();
        let dictionary = request.dictionary();

        assert_eq!(
            dictionary.get("@ApImg4Ticket").and_then(Value::as_boolean),
            Some(true)
        );
        assert!(!dictionary.contains_key("@Cryptex1,Ticket"));
        assert_eq!(
            dictionary.get("Ap,LocalPolicy").and_then(Value::as_data),
            Some([3, 4].as_slice())
        );
        assert_eq!(
            dictionary
                .get("Ap,NextStageCryptex1IM4MHash")
                .and_then(Value::as_data),
            Some([7, 8].as_slice())
        );
        assert_eq!(
            dictionary.get("ApSecurityMode").and_then(Value::as_boolean),
            Some(true)
        );
    }

    #[test]
    fn cryptex_local_policy_requires_local_boot() {
        let mut parameters = Dictionary::new();
        parameters.insert("Ap,LocalPolicy".into(), Value::Data(vec![3, 4]));

        assert!(matches!(
            TssRequest::for_cryptex(&parameters),
            Err(TssError::MissingCryptexParameter("Ap,LocalBoot"))
        ));
    }

    #[test]
    fn parses_success_response() {
        let response = concat!(
            "STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=",
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<plist version="1.0"><dict><key>ApImg4Ticket</key><data>AQID</data></dict></plist>"#
        );

        let response = parse_response(response).unwrap();
        assert!(response.dictionary().contains_key("ApImg4Ticket"));
    }

    #[test]
    fn preserves_rejection_message() {
        let error = parse_response("STATUS=94&MESSAGE=This device isn't eligible").unwrap_err();
        assert!(
            matches!(error, TssError::Rejected(message) if message == "This device isn't eligible")
        );
    }

    #[test]
    fn applies_matching_restore_request_rules() {
        let mut input = Dictionary::new();
        let mut parameters = Dictionary::new();
        parameters.insert("ApProductionMode".into(), true.into());

        let mut conditions = Dictionary::new();
        conditions.insert("ApRawProductionMode".into(), true.into());
        let mut actions = Dictionary::new();
        actions.insert("EPRO".into(), true.into());
        actions.insert("Skip".into(), 255_u64.into());
        let mut rule = Dictionary::new();
        rule.insert("Conditions".into(), conditions.into());
        rule.insert("Actions".into(), actions.into());

        apply_restore_request_rules(&mut input, &parameters, &[rule.into()]);

        assert_eq!(input.get("EPRO").and_then(Value::as_boolean), Some(true));
        assert!(!input.contains_key("Skip"));
    }

    #[test]
    fn builds_request_from_trusted_manifest_components() {
        let manifest = BuildManifest::from_reader(Cursor::new(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>10.3.3</string>
<key>ProductBuildVersion</key><string>14G60</string>
<key>SupportedProductTypes</key><array><string>iPhone6,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n51ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>KernelCache</key><dict>
<key>Digest</key><data>AQID</data><key>Trusted</key><true/>
<key>Info</key><dict><key>Path</key><string>kernelcache</string></dict>
</dict></dict>
</dict></array>
</dict></plist>"#,
        ))
        .unwrap();
        let identity = manifest
            .select_identity(&BoardConfig::from("n51"), RestoreBehavior::Erase)
            .unwrap();
        let parameters = ApParameters::new(1, 0x8960, Ecid::new(42));

        let request = TssRequest::for_build_identity(identity, &parameters);

        assert_eq!(
            request
                .dictionary()
                .get("ApECID")
                .and_then(Value::as_unsigned_integer),
            Some(42)
        );
        let kernel = request
            .dictionary()
            .get("KernelCache")
            .and_then(Value::as_dictionary)
            .unwrap();
        assert!(kernel.contains_key("Digest"));
        assert!(!kernel.contains_key("Info"));
    }

    #[test]
    fn builds_baseband_ticket_request() {
        let manifest = BuildManifest::from_reader(Cursor::new(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>8.4.1</string>
<key>ProductBuildVersion</key><string>12H321</string>
<key>SupportedProductTypes</key><array><string>iPhone4,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>ApBoardID</key><string>0x08</string><key>ApChipID</key><string>0x8940</string>
<key>ApSecurityDomain</key><string>0x01</string><key>UniqueBuildID</key><data>AQID</data>
<key>Info</key><dict><key>DeviceClass</key><string>n94ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>BasebandFirmware</key><dict><key>Digest</key><data>BAUG</data>
<key>Info</key><dict><key>Path</key><string>baseband.bbfw</string></dict></dict></dict>
</dict></array></dict></plist>"#,
        ))
        .unwrap();
        let identity = manifest
            .select_identity(&BoardConfig::from("n94"), RestoreBehavior::Erase)
            .unwrap();
        let parameters = BasebandParameters::new(Ecid::new(42), 0x5a00e1, 257, vec![1, 2]);

        let request = TssRequest::for_baseband(identity, &parameters).unwrap();

        assert_eq!(
            request
                .dictionary()
                .get("BbGoldCertId")
                .and_then(Value::as_unsigned_integer),
            Some(257)
        );
        let firmware = request
            .dictionary()
            .get("BasebandFirmware")
            .and_then(Value::as_dictionary)
            .unwrap();
        assert!(!firmware.contains_key("Info"));
    }
}
