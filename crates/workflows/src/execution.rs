use std::fmt;

use legacy_ios_firmware::{FirmwareArchive, FirmwareError, SigningTicket, TicketError};
use legacy_ios_restore::PreparedRestoreData;
use plist::{Dictionary, Value};
use thiserror::Error;

use crate::{
    ComponentPersonalizer, DestructiveConsent, PersonalizationError, PlanId, RestorePlan, SepPolicy,
};

const BOOT_COMPONENTS: &[&str] = &[
    "iBSS",
    "iBEC",
    "RestoreLogo",
    "RestoreRamDisk",
    "RestoreDeviceTree",
    "RestoreSEP",
    "RestoreKernelCache",
];

pub struct RestorePreparation {
    plan_id: PlanId,
    boot_components: Vec<PreparedBootComponent>,
    restored_data: PreparedRestoreData,
    filesystem_path: String,
    recovery_ticket: Option<Vec<u8>>,
    boot_nonce: Option<String>,
    build_major: u32,
    send_rsep: bool,
    ticket_dictionary: Dictionary,
    exploit_policy: crate::ExploitPolicy,
}

impl RestorePreparation {
    pub fn with_ticket(
        plan: &RestorePlan,
        consent: &DestructiveConsent,
        ticket: SigningTicket,
        flash_version_1: bool,
    ) -> Result<Self, RestorePreparationError> {
        Self::prepare(plan, consent, Some(ticket), flash_version_1)
    }

    /// Prepare a restore without a signing ticket: components keep their raw
    /// archive bytes and no ticket is sent to the device or `restored`.
    pub fn without_ticket(
        plan: &RestorePlan,
        consent: &DestructiveConsent,
        flash_version_1: bool,
    ) -> Result<Self, RestorePreparationError> {
        Self::prepare(plan, consent, None, flash_version_1)
    }

    fn prepare(
        plan: &RestorePlan,
        consent: &DestructiveConsent,
        ticket: Option<SigningTicket>,
        flash_version_1: bool,
    ) -> Result<Self, RestorePreparationError> {
        if !plan.accepts(consent) {
            return Err(RestorePreparationError::ConsentMismatch);
        }
        if let Some(ticket) = &ticket
            && let Some(ecid) = plan.device().ecid()
        {
            ticket.verify_ecid(ecid)?;
        }
        let archive = FirmwareArchive::open(plan.firmware())?;
        let manifest = archive.build_manifest()?;
        if manifest.product_version().as_str() != plan.product_version()
            || manifest.build_id().as_str() != plan.build_id()
        {
            return Err(RestorePreparationError::FirmwareChanged);
        }
        let board = plan
            .device()
            .board_config()
            .ok_or(RestorePreparationError::MissingBoardConfig)?;
        let identity = manifest.select_identity(board, plan.behavior())?.clone();
        let build_major = plan
            .build_id()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .map_err(|_| RestorePreparationError::InvalidBuildId)?;
        let filesystem_path = identity.component_path("OS")?.to_owned();
        let recovery_ticket = ticket
            .as_ref()
            .and_then(|ticket| ticket.dictionary().get("APTicket"))
            .and_then(Value::as_data)
            .map(ToOwned::to_owned);
        let ticket_dictionary = ticket
            .as_ref()
            .map(|ticket| ticket.dictionary().clone())
            .unwrap_or_default();
        let boot_nonce = if plan.nonce_policy() == crate::NoncePolicy::Auto
            && let Some(ticket) = &ticket
        {
            let generator = ticket
                .generator()
                .ok_or(RestorePreparationError::MissingGenerator)?;
            Some(
                generator
                    .parse::<legacy_ios_core::BootNonce>()
                    .map_err(|_| RestorePreparationError::InvalidGenerator(generator.to_owned()))?
                    .to_string(),
            )
        } else {
            None
        };
        let personalizer =
            ComponentPersonalizer::new(archive, identity.clone(), ticket_dictionary.clone());
        // futurerestore --rdsk/--rkrn: the override files replace the archive
        // bytes of RestoreRamDisk/RestoreKernelCache and are still
        // personalized with the ticket afterwards (idevicerestore
        // recovery.c's personalize_component call chain).
        let overrides = plan
            .boot_overrides()
            .map(|overrides| {
                Ok::<_, std::io::Error>((
                    std::fs::read(&overrides.rdsk)?,
                    std::fs::read(&overrides.rkrn)?,
                ))
            })
            .transpose()?;
        let include_sep = !matches!(plan.sep_policy(), SepPolicy::None);
        let sep = match plan.sep_policy() {
            SepPolicy::Auto | SepPolicy::None => None,
            SepPolicy::Provided(path) => {
                let archive = FirmwareArchive::open(path)?;
                let manifest = archive.build_manifest()?;
                let identity = manifest.select_identity(board, plan.behavior())?.clone();
                if !identity.manifest().contains_key("RestoreSEP") {
                    return Err(RestorePreparationError::MissingProvidedSep);
                }
                Some((
                    ComponentPersonalizer::new(
                        archive,
                        identity.clone(),
                        ticket_dictionary.clone(),
                    ),
                    identity,
                ))
            }
        };
        let boot_components = BOOT_COMPONENTS
            .iter()
            .copied()
            .filter(|name| {
                if name == &"RestoreSEP" {
                    include_sep && (identity.manifest().contains_key(name) || sep.is_some())
                } else {
                    identity.manifest().contains_key(name)
                }
            })
            .map(|name| {
                let source = if name == "RestoreSEP" {
                    sep.as_ref().map(|(personalizer, _)| personalizer)
                } else {
                    None
                }
                .unwrap_or(&personalizer);
                let override_data = match (name, &overrides) {
                    ("RestoreRamDisk", Some((rdsk, _))) => Some(rdsk.clone()),
                    ("RestoreKernelCache", Some((_, rkrn))) => Some(rkrn.clone()),
                    _ => None,
                };
                let data = match override_data {
                    Some(data) => personalizer.personalize_data(name, data)?,
                    None => source.personalize(name)?,
                };
                Ok(PreparedBootComponent {
                    name: name.to_owned(),
                    data,
                })
            })
            .collect::<Result<Vec<_>, RestorePreparationError>>()?;
        let mut restored_data = personalizer.prepare_restore_data(flash_version_1, include_sep)?;
        if let Some((sep, sep_identity)) = &sep {
            let mut nor = personalizer.nor_response(flash_version_1, include_sep)?;
            for (component, key) in [
                ("RestoreSEP", "RestoreSEPImageData"),
                ("SEP", "SEPImageData"),
                ("SepStage1", "SEPPatchImageData"),
            ] {
                if sep_identity.manifest().contains_key(component) {
                    nor.insert(key.into(), Value::Data(sep.personalize(component)?));
                }
            }
            restored_data = restored_data.with_nor(nor);
        }
        // Answer BuildIdentityDict requests with the target identity, rewritten
        // against the provided cryptex source when the plan calls for it
        // (idevicerestore restore_send_buildidentity, restore.c:5129-5207).
        let mut build_identity = identity.raw().clone();
        if let Some(crate::CryptexSource::Provided(path)) = plan.cryptex_source() {
            let source_archive = FirmwareArchive::open(path)?;
            let source_manifest = source_archive.build_manifest()?;
            let source_identity = source_manifest.select_identity(board, plan.behavior())?;
            build_identity = crate::rewrite_build_identity(&build_identity, source_identity.raw());
        }
        restored_data = restored_data.with_build_identity(build_identity);
        Ok(Self {
            plan_id: plan.id().clone(),
            boot_components,
            restored_data,
            filesystem_path,
            recovery_ticket,
            boot_nonce,
            build_major,
            send_rsep: plan.rsep_policy() == crate::RsepPolicy::Send,
            ticket_dictionary,
            exploit_policy: plan.exploit_policy(),
        })
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub fn boot_components(&self) -> &[PreparedBootComponent] {
        &self.boot_components
    }

    pub fn restored_data(&self) -> &PreparedRestoreData {
        &self.restored_data
    }

    pub fn filesystem_path(&self) -> &str {
        &self.filesystem_path
    }

    pub fn recovery_ticket(&self) -> Option<&[u8]> {
        self.recovery_ticket.as_deref()
    }

    pub fn boot_nonce(&self) -> Option<&str> {
        self.boot_nonce.as_deref()
    }

    pub const fn build_major(&self) -> u32 {
        self.build_major
    }

    /// Whether the boot chain uploads RestoreSEP and issues `rsepfirmware`
    /// (the resolved [`crate::RsepPolicy`]).
    pub const fn send_rsep(&self) -> bool {
        self.send_rsep
    }

    /// Signing ticket dictionary used for component path lookups and
    /// boot-object personalization.
    pub fn ticket_dictionary(&self) -> &Dictionary {
        &self.ticket_dictionary
    }

    pub const fn exploit_policy(&self) -> crate::ExploitPolicy {
        self.exploit_policy
    }
}

impl fmt::Debug for RestorePreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestorePreparation")
            .field("plan_id", &self.plan_id)
            .field("boot_components", &self.boot_components)
            .field("filesystem_path", &self.filesystem_path)
            .finish_non_exhaustive()
    }
}

pub struct PreparedBootComponent {
    name: String,
    data: Vec<u8>,
}

impl PreparedBootComponent {
    pub(crate) fn new(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            data,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for PreparedBootComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBootComponent")
            .field("name", &self.name)
            .field("bytes", &self.data.len())
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum RestorePreparationError {
    #[error("destructive consent does not match the restore plan")]
    ConsentMismatch,
    #[error("restore plan device has no board config")]
    MissingBoardConfig,
    #[error("firmware changed after restore planning")]
    FirmwareChanged,
    #[error("firmware build identifier has no numeric major version")]
    InvalidBuildId,
    #[error("nonce policy is automatic but the ticket has no generator")]
    MissingGenerator,
    #[error("ticket generator is not a valid boot nonce: {0}")]
    InvalidGenerator(String),
    #[error("provided SEP firmware has no RestoreSEP component")]
    MissingProvidedSep,
    #[error("boot component override read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error(transparent)]
    Personalization(#[from] PersonalizationError),
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::{BoardConfig, DeviceIdentity, Ecid, ProductType, Soc};
    use legacy_ios_firmware::{RestoreBehavior, SigningTicket};
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::{BasebandPolicy, ExploitPolicy, RestoreRequest, SepPolicy, TicketPolicy};

    #[test]
    fn binds_ticket_and_prepares_boot_components() {
        let firmware = firmware_fixture();
        let plan = RestorePlan::resolve(RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::None,
            sep: SepPolicy::Auto,
            rsep: crate::RsepPolicy::Auto,
            cryptex: crate::CryptexPolicy::Auto,
            cryptex_source: crate::CryptexSource::Target,
            exploit: ExploitPolicy::None,
            nonce: crate::NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        })
        .unwrap();
        let consent = plan.confirm_destructive();
        let ticket = SigningTicket::from_reader(std::io::Cursor::new(
            br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>APTicket</key><data>AQID</data><key>ApECID</key><integer>42</integer>
</dict></plist>"#,
        ))
        .unwrap();

        let prepared = RestorePreparation::with_ticket(&plan, &consent, ticket, false).unwrap();

        assert_eq!(prepared.filesystem_path(), "filesystem.dmg");
        assert_eq!(prepared.boot_components()[0].name(), "iBSS");
        assert_eq!(prepared.boot_components()[1].name(), "RestoreKernelCache");
        // iOS 7 targets skip the RestoreSEP upload by default.
        assert!(!prepared.send_rsep());
    }

    fn firmware_fixture() -> NamedTempFile {
        firmware_fixture_with(MANIFEST, &["filesystem.dmg", "ibss.img3", "kernel.img3"])
    }

    fn firmware_fixture_with(manifest: &str, entries: &[&str]) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        for path in entries {
            writer
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(path.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        file
    }

    #[test]
    fn prepares_without_ticket_using_raw_components() {
        let firmware = firmware_fixture();
        let plan = RestorePlan::resolve(RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Skip,
            baseband: BasebandPolicy::None,
            sep: SepPolicy::Auto,
            rsep: crate::RsepPolicy::Auto,
            cryptex: crate::CryptexPolicy::Auto,
            cryptex_source: crate::CryptexSource::Target,
            exploit: ExploitPolicy::AlreadyPwned,
            nonce: crate::NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        })
        .unwrap();
        let consent = plan.confirm_destructive();

        let prepared = RestorePreparation::without_ticket(&plan, &consent, false).unwrap();

        assert!(prepared.recovery_ticket().is_none());
        assert!(prepared.boot_nonce().is_none());
        assert_eq!(prepared.boot_components()[0].name(), "iBSS");
        assert_eq!(prepared.boot_components()[0].data(), b"ibss.img3");
    }

    #[test]
    fn boot_overrides_replace_archive_bytes() {
        let firmware = firmware_fixture();
        let mut rdsk = NamedTempFile::new().unwrap();
        rdsk.write_all(b"patched rdsk.im4p").unwrap();
        let mut rkrn = NamedTempFile::new().unwrap();
        rkrn.write_all(b"patched kcache.im4p").unwrap();
        let plan = RestorePlan::resolve(RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Skip,
            baseband: BasebandPolicy::None,
            sep: SepPolicy::Auto,
            rsep: crate::RsepPolicy::Auto,
            cryptex: crate::CryptexPolicy::Auto,
            cryptex_source: crate::CryptexSource::Target,
            exploit: ExploitPolicy::AlreadyPwned,
            nonce: crate::NoncePolicy::Manual,
            rdsk: Some(rdsk.path().to_owned()),
            rkrn: Some(rkrn.path().to_owned()),
        })
        .unwrap();
        // The ipx mode always sends RestoreSEP.
        assert_eq!(plan.rsep_policy(), crate::RsepPolicy::Send);

        let prepared =
            RestorePreparation::without_ticket(&plan, &plan.confirm_destructive(), false).unwrap();

        // Without a ticket the override bytes pass through unpersonalized.
        let kernel = prepared
            .boot_components()
            .iter()
            .find(|component| component.name() == "RestoreKernelCache")
            .unwrap();
        assert_eq!(kernel.data(), b"patched kcache.im4p");
        let ibss = prepared
            .boot_components()
            .iter()
            .find(|component| component.name() == "iBSS")
            .unwrap();
        assert_eq!(ibss.data(), b"ibss.img3");
    }

    #[test]
    fn sep_policy_none_omits_restore_sep_boot_component() {
        let firmware = firmware_fixture_with(
            MANIFEST_WITH_SEP,
            &["filesystem.dmg", "ibss.img3", "kernel.img3", "sep.img3"],
        );
        let request = |sep| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Skip,
            baseband: BasebandPolicy::None,
            sep,
            rsep: crate::RsepPolicy::Auto,
            cryptex: crate::CryptexPolicy::Auto,
            cryptex_source: crate::CryptexSource::Target,
            exploit: ExploitPolicy::AlreadyPwned,
            nonce: crate::NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };
        let plan = RestorePlan::resolve(request(SepPolicy::Auto)).unwrap();
        let prepared =
            RestorePreparation::without_ticket(&plan, &plan.confirm_destructive(), false).unwrap();
        assert!(
            prepared
                .boot_components()
                .iter()
                .any(|component| component.name() == "RestoreSEP")
        );

        let plan = RestorePlan::resolve(request(SepPolicy::None)).unwrap();
        let prepared =
            RestorePreparation::without_ticket(&plan, &plan.confirm_destructive(), false).unwrap();
        assert!(
            prepared
                .boot_components()
                .iter()
                .all(|component| component.name() != "RestoreSEP")
        );
    }

    const MANIFEST: &str = r#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>7.1.2</string><key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict><key>Info</key><dict><key>DeviceClass</key><string>n90ap</string>
<key>RestoreBehavior</key><string>Erase</string></dict><key>Manifest</key><dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>filesystem.dmg</string></dict></dict>
<key>iBSS</key><dict><key>Info</key><dict><key>Path</key><string>ibss.img3</string></dict></dict>
<key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernel.img3</string></dict></dict>
</dict></dict></array></dict></plist>"#;

    const MANIFEST_WITH_SEP: &str = r#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>7.1.2</string><key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict><key>Info</key><dict><key>DeviceClass</key><string>n90ap</string>
<key>RestoreBehavior</key><string>Erase</string></dict><key>Manifest</key><dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>filesystem.dmg</string></dict></dict>
<key>iBSS</key><dict><key>Info</key><dict><key>Path</key><string>ibss.img3</string></dict></dict>
<key>RestoreSEP</key><dict><key>Info</key><dict><key>Path</key><string>sep.img3</string></dict></dict>
<key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernel.img3</string></dict></dict>
</dict></dict></array></dict></plist>"#;
}
