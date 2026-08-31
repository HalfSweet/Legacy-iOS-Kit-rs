use std::fmt;

use legacy_ios_firmware::{FirmwareArchive, FirmwareError, SigningTicket, TicketError};
use legacy_ios_restore::PreparedRestoreData;
use plist::Value;
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
    build_major: u32,
    exploit_policy: crate::ExploitPolicy,
}

impl RestorePreparation {
    pub fn with_ticket(
        plan: &RestorePlan,
        consent: &DestructiveConsent,
        ticket: SigningTicket,
        flash_version_1: bool,
    ) -> Result<Self, RestorePreparationError> {
        if !plan.accepts(consent) {
            return Err(RestorePreparationError::ConsentMismatch);
        }
        if let Some(ecid) = plan.device().ecid() {
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
            .dictionary()
            .get("APTicket")
            .and_then(Value::as_data)
            .map(ToOwned::to_owned);
        let ticket_dictionary = ticket.dictionary().clone();
        let personalizer =
            ComponentPersonalizer::new(archive, identity.clone(), ticket_dictionary.clone());
        let sep = match plan.sep_policy() {
            SepPolicy::Auto => None,
            SepPolicy::Provided(path) => {
                let archive = FirmwareArchive::open(path)?;
                let manifest = archive.build_manifest()?;
                let identity = manifest.select_identity(board, plan.behavior())?.clone();
                if !identity.manifest().contains_key("RestoreSEP") {
                    return Err(RestorePreparationError::MissingProvidedSep);
                }
                Some((
                    ComponentPersonalizer::new(archive, identity.clone(), ticket_dictionary),
                    identity,
                ))
            }
        };
        let boot_components = BOOT_COMPONENTS
            .iter()
            .copied()
            .filter(|name| {
                identity.manifest().contains_key(name) || name == &"RestoreSEP" && sep.is_some()
            })
            .map(|name| {
                let source = if name == "RestoreSEP" {
                    sep.as_ref().map(|(personalizer, _)| personalizer)
                } else {
                    None
                }
                .unwrap_or(&personalizer);
                Ok(PreparedBootComponent {
                    name: name.to_owned(),
                    data: source.personalize(name)?,
                })
            })
            .collect::<Result<Vec<_>, RestorePreparationError>>()?;
        let mut restored_data = personalizer.prepare_restore_data(flash_version_1)?;
        if let Some((sep, sep_identity)) = &sep {
            let mut nor = personalizer.nor_response(flash_version_1)?;
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
        Ok(Self {
            plan_id: plan.id().clone(),
            boot_components,
            restored_data,
            filesystem_path,
            recovery_ticket,
            build_major,
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

    pub const fn build_major(&self) -> u32 {
        self.build_major
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
    #[error("provided SEP firmware has no RestoreSEP component")]
    MissingProvidedSep,
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
            exploit: ExploitPolicy::None,
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
    }

    fn firmware_fixture() -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(MANIFEST.as_bytes()).unwrap();
        for path in ["filesystem.dmg", "ibss.img3", "kernel.img3"] {
            writer
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(path.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        file
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
}
