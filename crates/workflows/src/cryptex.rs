//! Cryptex1 restore strategy (futurerestore dev branch, iOS 16+): boot-object
//! answers, live Cryptex1/Cryptex1LocalPolicy TSS signing, and the
//! BuildIdentityDict rewrite against a separate cryptex source.

use std::path::Path;

use legacy_ios_firmware::{
    BuildIdentity, FirmwareArchive, FirmwareError, TssClient, TssError, TssRequest,
};
use legacy_ios_restore::{
    BootObjectImage, BootObjectRequest, DataRequest, DataType, RestoredError,
};
use plist::{Dictionary, Value};
use thiserror::Error;
use tracing::warn;

use crate::{ComponentPersonalizer, CryptexSource, PersonalizationError, RestorePlan};

/// Manifest keys whose entries are replaced by the cryptex source during the
/// BuildIdentityDict rewrite (idevicerestore restore.c:5161-5182). The first
/// six are also the boot-object component names answered from the cryptex
/// source.
const CRYPTEX_MANIFEST_KEYS: &[&str] = &[
    "Cryptex1,SystemOS",
    "Cryptex1,SystemVolume",
    "Cryptex1,SystemTrustCache",
    "Cryptex1,AppOS",
    "Cryptex1,AppVolume",
    "Cryptex1,AppTrustCache",
    "Cryptex1,MobileAssetBrainOS",
    "Cryptex1,MobileAssetBrainVolume",
    "Cryptex1,MobileAssetBrainTrustCache",
];

/// The six Cryptex1 boot-object component names answered from the cryptex
/// source (restore.c:4934-5059).
const CRYPTEX_COMPONENTS: &[&str] = &[
    "Cryptex1,SystemOS",
    "Cryptex1,SystemVolume",
    "Cryptex1,SystemTrustCache",
    "Cryptex1,AppOS",
    "Cryptex1,AppVolume",
    "Cryptex1,AppTrustCache",
];

/// Whether a boot-object component name is one of the six Cryptex1 payloads
/// answered from the cryptex source.
pub fn is_cryptex_component(name: &str) -> bool {
    CRYPTEX_COMPONENTS.contains(&name)
}

/// Whether a FirmwareUpdaterData request targets the Cryptex1 or
/// Cryptex1LocalPolicy updater (idevicerestore restore.c:4315).
pub fn is_cryptex_updater(request: &DataRequest) -> bool {
    matches!(
        request
            .message()
            .get("Arguments")
            .and_then(Value::as_dictionary)
            .and_then(|arguments| arguments.get("MessageArgUpdaterName"))
            .and_then(Value::as_string),
        Some("Cryptex1" | "Cryptex1LocalPolicy")
    )
}

/// Rewrite a target build identity against a cryptex source identity
/// (idevicerestore `restore_send_buildidentity`, restore.c:5146-5185): copy
/// the three top-level `Cryptex1,*` version keys, replace the `Info` cryptex
/// sizes, and swap the cryptex manifest entries. Keys missing from the source
/// are dropped from the target manifest / left untouched elsewhere.
pub fn rewrite_build_identity(target: &Dictionary, source: &Dictionary) -> Dictionary {
    let mut identity = target.clone();
    for key in [
        "Cryptex1,Version",
        "Cryptex1,PreauthorizationVersion",
        "Cryptex1,FakeRoot",
    ] {
        if let Some(value) = source.get(key) {
            identity.insert(key.into(), value.clone());
        }
    }
    if let Some(mut info) = identity.remove("Info").and_then(Value::into_dictionary) {
        let source_info = source.get("Info").and_then(Value::as_dictionary);
        for key in ["Cryptex1,AppOSSize", "Cryptex1,SystemOSSize"] {
            info.remove(key);
            if let Some(value) = source_info.and_then(|info| info.get(key)) {
                info.insert(key.into(), value.clone());
            }
        }
        identity.insert("Info".into(), info.into());
    }
    if let Some(mut manifest) = identity.remove("Manifest").and_then(Value::into_dictionary) {
        let source_manifest = source.get("Manifest").and_then(Value::as_dictionary);
        for key in CRYPTEX_MANIFEST_KEYS {
            manifest.remove(key);
            if let Some(value) = source_manifest.and_then(|manifest| manifest.get(key)) {
                manifest.insert((*key).into(), value.clone());
            }
        }
        identity.insert("Manifest".into(), manifest.into());
    }
    identity
}

#[derive(Clone, Debug)]
pub struct CryptexResolver {
    archive: FirmwareArchive,
    identity: BuildIdentity,
    ticket: Dictionary,
    source: Option<CryptexSourceFirmware>,
    tss: TssClient,
}

#[derive(Clone, Debug)]
struct CryptexSourceFirmware {
    archive: FirmwareArchive,
    identity: BuildIdentity,
}

impl CryptexResolver {
    pub fn new(
        plan: &RestorePlan,
        ticket: Dictionary,
        tss: TssClient,
    ) -> Result<Self, CryptexRequestError> {
        let board = plan
            .device()
            .board_config()
            .ok_or(CryptexRequestError::MissingBoardConfig)?;
        let (archive, identity) = open_identity(plan.firmware(), board, plan.behavior())?;
        let source = match plan.cryptex_source() {
            Some(CryptexSource::Provided(path)) => {
                let (archive, identity) = open_identity(path, board, plan.behavior())?;
                Some(CryptexSourceFirmware { archive, identity })
            }
            Some(CryptexSource::Target) | None => None,
        };
        Ok(Self {
            archive,
            identity,
            ticket,
            source,
            tss,
        })
    }

    /// Resolve a `SourceBootObjectV4`/`PersonalizedBootObjectV3` request into
    /// the payload bytes to stream as a `FileData` sequence (idevicerestore
    /// restore.c:4842-5073 / 4722-4840).
    pub async fn boot_object(&self, request: &DataRequest) -> Result<Vec<u8>, CryptexRequestError> {
        let object = request.boot_object()?;
        // V3 personalizes against the AP ticket; V4 sends raw bytes.
        let personalized = matches!(request.data_type(), DataType::PersonalizedBootObjectV3);
        let resolver = self.clone();
        tokio::task::spawn_blocking(move || resolver.boot_object_data(&object, personalized))
            .await
            .map_err(|error| CryptexRequestError::Task(error.to_string()))?
    }

    fn boot_object_data(
        &self,
        object: &BootObjectRequest,
        personalized: bool,
    ) -> Result<Vec<u8>, CryptexRequestError> {
        match object.image() {
            BootObjectImage::GlobalManifest => {
                let variant = match (object.variant(), personalized) {
                    (Some(variant), _) => variant.to_owned(),
                    // V3 derives the variant from the identity's MacOSVariant
                    // (extract_macos_variant, restore.c:4600).
                    (None, true) => self.identity_info("MacOSVariant")?.to_owned(),
                    (None, false) => return Err(CryptexRequestError::MissingArgument("Variant")),
                };
                let device_class = self.identity_info("DeviceClass")?;
                // The global manifest path is hardcoded; the build manifest
                // has no pointer to it (restore.c:4646-4649).
                let path =
                    format!("Firmware/Manifests/restore/{variant}/apticket.{device_class}.im4m");
                Ok(self.archive.read_entry(&path)?)
            }
            BootObjectImage::RestoreVersion => {
                Ok(self.archive.read_entry("RestoreVersion.plist")?)
            }
            BootObjectImage::SystemVersion => Ok(self.archive.read_entry("SystemVersion.plist")?),
            BootObjectImage::Component(name) if is_cryptex_component(name) => {
                // Cryptex payloads ship unpersonalized from the cryptex
                // source (the target IPSW itself by default).
                let (archive, identity) = match &self.source {
                    Some(source) => (&source.archive, &source.identity),
                    None => (&self.archive, &self.identity),
                };
                let path = identity.component_path(name)?.to_owned();
                Ok(archive.read_entry(&path)?)
            }
            BootObjectImage::Component(name) if personalized => {
                let personalizer = ComponentPersonalizer::new(
                    self.archive.clone(),
                    self.identity.clone(),
                    self.ticket.clone(),
                );
                Ok(personalizer.personalize(name)?)
            }
            BootObjectImage::Component(name) => {
                // V4: path from the TSS response entry first, then the build
                // identity; the component ships unpersonalized.
                let path = self
                    .ticket
                    .get(name)
                    .and_then(Value::as_dictionary)
                    .and_then(|entry| entry.get("Path"))
                    .and_then(Value::as_string)
                    .map(ToOwned::to_owned)
                    .map_or_else(
                        || self.identity.component_path(name).map(ToOwned::to_owned),
                        Ok,
                    )?;
                Ok(self.archive.read_entry(&path)?)
            }
        }
    }

    /// Answer a Cryptex1/Cryptex1LocalPolicy FirmwareUpdaterData request with
    /// a live TSS signing (idevicerestore
    /// `restore_get_cryptex1_firmware_data`, restore.c:3980-4172, dispatched
    /// at restore.c:4315-4328). On TSS failure with a separate cryptex
    /// source, retry once against the source identity.
    pub async fn firmware_updater(
        &self,
        request: &DataRequest,
    ) -> Result<Dictionary, CryptexRequestError> {
        let arguments = request
            .message()
            .get("Arguments")
            .and_then(Value::as_dictionary)
            .ok_or(CryptexRequestError::MissingArgument("Arguments"))?;
        let parameters = self.cryptex_parameters(arguments, &self.identity)?;
        let response = match self.tss.send(&TssRequest::for_cryptex(&parameters)?).await {
            Ok(response) => response,
            Err(error) => {
                let Some(source) = &self.source else {
                    return Err(error.into());
                };
                warn!(%error, "cryptex TSS failed; retrying with the source identity");
                let parameters = self.cryptex_parameters(arguments, &source.identity)?;
                self.tss
                    .send(&TssRequest::for_cryptex(&parameters)?)
                    .await?
            }
        };
        let response = response.into_dictionary();
        let response_tag = arguments
            .get("DeviceGeneratedTags")
            .and_then(Value::as_dictionary)
            .and_then(|tags| tags.get("ResponseTags"))
            .and_then(Value::as_array)
            .and_then(|tags| tags.first())
            .and_then(Value::as_string)
            .unwrap_or("Cryptex1,Ticket");
        if !response.contains_key(response_tag) {
            // Upstream only warns here; the response is still returned.
            warn!(
                tag = response_tag,
                "cryptex TSS response misses the expected tag"
            );
        }
        let mut dict = Dictionary::new();
        dict.insert("FirmwareResponseData".into(), response.into());
        Ok(dict)
    }

    /// Merge the cryptex TSS parameters: `MessageArgInfo`, the
    /// device-requested `BuildIdentityTags` copied from `tag_identity`,
    /// required defaults, and the `DeviceGeneratedRequest`
    /// (restore.c:4012-4052).
    fn cryptex_parameters(
        &self,
        arguments: &Dictionary,
        tag_identity: &BuildIdentity,
    ) -> Result<Dictionary, CryptexRequestError> {
        let mut parameters = arguments
            .get("MessageArgInfo")
            .and_then(Value::as_dictionary)
            .cloned()
            .ok_or(CryptexRequestError::MissingArgument("MessageArgInfo"))?;
        if let Some(tags) = arguments
            .get("DeviceGeneratedTags")
            .and_then(Value::as_dictionary)
            .and_then(|tags| tags.get("BuildIdentityTags"))
            .and_then(Value::as_array)
        {
            for key in tags.iter().filter_map(Value::as_string) {
                if let Some(value) = tag_identity.raw().get(key) {
                    parameters.insert(key.to_owned(), value.clone());
                }
            }
        }
        if !parameters.contains_key("ApProductionMode") {
            parameters.insert("ApProductionMode".into(), true.into());
        }
        if !parameters.contains_key("ApSecurityMode") {
            parameters.insert("ApSecurityMode".into(), true.into());
        }
        // ApChipID/ApBoardID always default from the target identity, even on
        // the source-identity retry (restore.c:4038-4043).
        for key in ["ApChipID", "ApBoardID"] {
            if !parameters.contains_key(key)
                && let Some(value) = self.identity.raw().get(key)
            {
                parameters.insert(key.into(), value.clone());
            }
        }
        let generated = arguments
            .get("DeviceGeneratedRequest")
            .and_then(Value::as_dictionary)
            .ok_or(CryptexRequestError::MissingArgument(
                "DeviceGeneratedRequest",
            ))?;
        for (key, value) in generated {
            parameters.insert(key.clone(), value.clone());
        }
        Ok(parameters)
    }

    fn identity_info(&self, key: &'static str) -> Result<&str, CryptexRequestError> {
        self.identity
            .raw()
            .get("Info")
            .and_then(Value::as_dictionary)
            .and_then(|info| info.get(key))
            .and_then(Value::as_string)
            .ok_or(CryptexRequestError::MissingIdentityValue(key))
    }
}

fn open_identity(
    firmware: &Path,
    board: &legacy_ios_core::BoardConfig,
    behavior: legacy_ios_firmware::RestoreBehavior,
) -> Result<(FirmwareArchive, BuildIdentity), CryptexRequestError> {
    let archive = FirmwareArchive::open(firmware)?;
    let manifest = archive.build_manifest()?;
    let identity = manifest.select_identity(board, behavior)?.clone();
    Ok((archive, identity))
}

#[derive(Debug, Error)]
pub enum CryptexRequestError {
    #[error("cryptex handling is disabled for this restore")]
    Disabled,
    #[error("restore plan has no board config")]
    MissingBoardConfig,
    #[error("cryptex request is missing {0}")]
    MissingArgument(&'static str),
    #[error("build identity is missing {0}")]
    MissingIdentityValue(&'static str),
    #[error("cryptex worker task failed: {0}")]
    Task(String),
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Tss(#[from] TssError),
    #[error(transparent)]
    Restored(#[from] RestoredError),
    #[error(transparent)]
    Personalization(#[from] PersonalizationError),
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::{BoardConfig, DeviceIdentity, Ecid, ProductType, Soc};
    use legacy_ios_firmware::RestoreBehavior;
    use legacy_ios_restore::RestoredMessage;
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::{
        BasebandPolicy, CryptexPolicy, ExploitPolicy, NoncePolicy, RestoreRequest, RsepPolicy,
        SepPolicy, TicketPolicy,
    };

    #[test]
    fn rewrites_cryptex_keys_from_the_source_identity() {
        let mut target_info = Dictionary::new();
        target_info.insert("DeviceClass".into(), "d22ap".into());
        target_info.insert("Cryptex1,AppOSSize".into(), 100_u64.into());
        target_info.insert("Cryptex1,SystemOSSize".into(), 200_u64.into());
        let mut target_manifest = Dictionary::new();
        target_manifest.insert("Cryptex1,SystemOS".into(), "target-sysos".into());
        target_manifest.insert("Cryptex1,AppOS".into(), "target-appos".into());
        target_manifest.insert("iBoot".into(), "target-iboot".into());
        let mut target = Dictionary::new();
        target.insert("Cryptex1,Version".into(), 1_u64.into());
        target.insert("Info".into(), target_info.into());
        target.insert("Manifest".into(), target_manifest.into());

        let mut source_info = Dictionary::new();
        source_info.insert("Cryptex1,AppOSSize".into(), 300_u64.into());
        let mut source_manifest = Dictionary::new();
        source_manifest.insert("Cryptex1,SystemOS".into(), "source-sysos".into());
        source_manifest.insert("Cryptex1,AppOS".into(), "source-appos".into());
        let mut source = Dictionary::new();
        source.insert("Cryptex1,Version".into(), 2_u64.into());
        source.insert("Cryptex1,FakeRoot".into(), true.into());
        source.insert("Info".into(), source_info.into());
        source.insert("Manifest".into(), source_manifest.into());

        let rewritten = rewrite_build_identity(&target, &source);

        assert_eq!(
            rewritten
                .get("Cryptex1,Version")
                .and_then(Value::as_unsigned_integer),
            Some(2)
        );
        assert_eq!(
            rewritten
                .get("Cryptex1,FakeRoot")
                .and_then(Value::as_boolean),
            Some(true)
        );
        let info = rewritten
            .get("Info")
            .and_then(Value::as_dictionary)
            .unwrap();
        // Sizes missing from the source are dropped from the target.
        assert!(!info.contains_key("Cryptex1,SystemOSSize"));
        assert_eq!(
            info.get("Cryptex1,AppOSSize")
                .and_then(Value::as_unsigned_integer),
            Some(300)
        );
        assert_eq!(
            info.get("DeviceClass").and_then(Value::as_string),
            Some("d22ap")
        );
        let manifest = rewritten
            .get("Manifest")
            .and_then(Value::as_dictionary)
            .unwrap();
        assert_eq!(
            manifest.get("Cryptex1,SystemOS").and_then(Value::as_string),
            Some("source-sysos")
        );
        assert_eq!(
            manifest.get("Cryptex1,AppOS").and_then(Value::as_string),
            Some("source-appos")
        );
        // Entries missing from the source are removed; unrelated entries stay.
        assert!(!manifest.contains_key("Cryptex1,AppVolume"));
        assert_eq!(
            manifest.get("iBoot").and_then(Value::as_string),
            Some("target-iboot")
        );
    }

    #[tokio::test]
    async fn answers_boot_objects_from_the_target_ipsw() {
        let firmware = cryptex_firmware_fixture();
        let resolver = resolver_fixture(&firmware, None);

        let restore_version = boot_request("PersonalizedBootObjectV3", "__RestoreVersion__", None);
        let data = resolver.boot_object(&restore_version).await.unwrap();
        assert_eq!(data, b"restore-version");

        // Regular components resolve through the identity path; without a
        // ticket they ship unpersonalized.
        let iboot = boot_request("SourceBootObjectV4", "iBoot", None);
        let data = resolver.boot_object(&iboot).await.unwrap();
        assert_eq!(data, b"iboot");

        // Cryptex components ship raw from the target archive by default.
        let sysos = boot_request("SourceBootObjectV4", "Cryptex1,SystemOS", None);
        let data = resolver.boot_object(&sysos).await.unwrap();
        assert_eq!(data, b"sysos");

        // V4 requires Arguments.Variant for the global manifest.
        let global = boot_request("SourceBootObjectV4", "__GlobalManifest__", None);
        assert!(matches!(
            resolver.boot_object(&global).await,
            Err(CryptexRequestError::MissingArgument("Variant"))
        ));
        let global = boot_request(
            "SourceBootObjectV4",
            "__GlobalManifest__",
            Some("Customer Erase Install (IPSW)"),
        );
        let data = resolver.boot_object(&global).await.unwrap();
        assert_eq!(data, b"global-manifest");
    }

    #[tokio::test]
    async fn answers_cryptex_components_from_the_provided_source() {
        let target = cryptex_firmware_fixture();
        let source = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(source.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                MANIFEST
                    .replace("cryptex/system.dmg", "source/system.dmg")
                    .as_bytes(),
            )
            .unwrap();
        writer
            .start_file("source/system.dmg", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"source-sysos").unwrap();
        writer.finish().unwrap();

        let resolver = resolver_fixture(&target, Some(source.path()));
        let sysos = boot_request("SourceBootObjectV4", "Cryptex1,SystemOS", None);
        let data = resolver.boot_object(&sysos).await.unwrap();
        assert_eq!(data, b"source-sysos");
    }

    #[test]
    fn merges_cryptex_tss_parameters() {
        let firmware = cryptex_firmware_fixture();
        let resolver = resolver_fixture(&firmware, None);

        let mut info = Dictionary::new();
        info.insert("Cryptex1,ChipID".into(), 0x8020_u64.into());
        let mut tags = Dictionary::new();
        tags.insert(
            "BuildIdentityTags".into(),
            Value::Array(vec!["Ap,OSLongVersion".into(), "Missing".into()]),
        );
        tags.insert(
            "ResponseTags".into(),
            Value::Array(vec!["Cryptex1,Ticket".into()]),
        );
        let mut generated = Dictionary::new();
        generated.insert("ApECID".into(), 42_u64.into());
        let mut arguments = Dictionary::new();
        arguments.insert("MessageArgInfo".into(), info.into());
        arguments.insert("DeviceGeneratedTags".into(), tags.into());
        arguments.insert("DeviceGeneratedRequest".into(), generated.into());

        let parameters = resolver
            .cryptex_parameters(&arguments, &resolver.identity)
            .unwrap();

        assert_eq!(
            parameters
                .get("Cryptex1,ChipID")
                .and_then(Value::as_unsigned_integer),
            Some(0x8020)
        );
        assert_eq!(
            parameters
                .get("Ap,OSLongVersion")
                .and_then(Value::as_string),
            Some("16.7.10")
        );
        // Identity keys not listed in BuildIdentityTags are not copied.
        assert!(!parameters.contains_key("Missing"));
        assert_eq!(
            parameters
                .get("ApProductionMode")
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            parameters.get("ApSecurityMode").and_then(Value::as_boolean),
            Some(true)
        );
        // ApChipID/ApBoardID default from the target identity.
        assert_eq!(
            parameters
                .get("ApChipID")
                .and_then(Value::as_unsigned_integer),
            Some(0x8020)
        );
        assert_eq!(
            parameters
                .get("ApECID")
                .and_then(Value::as_unsigned_integer),
            Some(42)
        );
    }

    #[test]
    fn cryptex_parameters_require_device_generated_request() {
        let firmware = cryptex_firmware_fixture();
        let resolver = resolver_fixture(&firmware, None);

        let mut arguments = Dictionary::new();
        arguments.insert("MessageArgInfo".into(), Dictionary::new().into());

        assert!(matches!(
            resolver.cryptex_parameters(&arguments, &resolver.identity),
            Err(CryptexRequestError::MissingArgument(
                "DeviceGeneratedRequest"
            ))
        ));
    }

    #[test]
    fn detects_cryptex_updater_requests() {
        let mut arguments = Dictionary::new();
        arguments.insert("MessageArgUpdaterName".into(), "Cryptex1LocalPolicy".into());
        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), "FirmwareUpdaterData".into());
        message.insert("Arguments".into(), arguments.into());
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        assert!(is_cryptex_updater(&request));

        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), "FirmwareUpdaterData".into());
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        assert!(!is_cryptex_updater(&request));
    }

    fn boot_request(data_type: &str, image_name: &str, variant: Option<&str>) -> DataRequest {
        let mut arguments = Dictionary::new();
        arguments.insert("ImageName".into(), image_name.into());
        if let Some(variant) = variant {
            arguments.insert("Variant".into(), variant.into());
        }
        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), data_type.into());
        message.insert("Arguments".into(), arguments.into());
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        request
    }

    fn resolver_fixture(firmware: &NamedTempFile, source: Option<&Path>) -> CryptexResolver {
        let plan = RestorePlan::resolve(RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone10,3"), Soc::A11)
                .with_board_config(BoardConfig::from("d22"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Skip,
            baseband: BasebandPolicy::None,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            cryptex: CryptexPolicy::Auto,
            cryptex_source: source.map_or(CryptexSource::Target, |path| {
                CryptexSource::Provided(path.to_owned())
            }),
            exploit: ExploitPolicy::AlreadyPwned,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        })
        .unwrap();
        CryptexResolver::new(&plan, Dictionary::new(), TssClient::new()).unwrap()
    }

    const MANIFEST: &str = r#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>16.7.10</string><key>ProductBuildVersion</key><string>20H350</string>
<key>SupportedProductTypes</key><array><string>iPhone10,3</string></array>
<key>BuildIdentities</key><array><dict>
<key>ApChipID</key><integer>32800</integer><key>ApBoardID</key><integer>12</integer>
<key>Ap,OSLongVersion</key><string>16.7.10</string>
<key>Info</key><dict><key>DeviceClass</key><string>d22ap</string>
<key>RestoreBehavior</key><string>Erase</string>
<key>MacOSVariant</key><string>Customer Erase Install (IPSW)</string></dict>
<key>Manifest</key><dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>filesystem.dmg</string></dict></dict>
<key>iBoot</key><dict><key>Info</key><dict><key>Path</key><string>iboot.im4p</string></dict></dict>
<key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>cryptex/system.dmg</string></dict></dict>
</dict></dict></array></dict></plist>"#;

    fn cryptex_firmware_fixture() -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(MANIFEST.as_bytes()).unwrap();
        for (path, data) in [
            ("filesystem.dmg", &b"filesystem"[..]),
            ("iboot.im4p", b"iboot"),
            ("cryptex/system.dmg", b"sysos"),
            ("RestoreVersion.plist", b"restore-version"),
            ("SystemVersion.plist", b"system-version"),
            (
                "Firmware/Manifests/restore/Customer Erase Install (IPSW)/apticket.d22ap.im4m",
                b"global-manifest",
            ),
        ] {
            writer
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        file
    }
}
