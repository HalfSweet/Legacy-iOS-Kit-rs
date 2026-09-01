//! Restore-side wiring for powdersn0w custom IPSWs, mirroring the
//! `restore_idevicerestore` invocation (restore.sh:6152-6203: an erase
//! downgrade of the custom IPSW, always with a local blob) and the ticket
//! provenance of `restore_deviceprepare` (restore.sh:6544-6570). The blob is
//! never the target version's: A4 restores fetch the device's latest-version
//! ticket live (7.1.2/6.1.3/5.1.1 stay OTA-signed; upstream uses tsschecker),
//! while A5/A5X/A6/A6X restores require a user-supplied base-version blob.
//!
//! A4 powder targets 3.x and 4.0-4.2.x are rejected here: upstream routes
//! them through the two-stage multipart flow (`restore_prepare`,
//! restore.sh:6596-6616), which `crate::multipart` implements.

use std::{fmt, path::PathBuf};

use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{DeviceIdentity, IosVersion, Soc};
use legacy_ios_firmware::{FirmwareArchive, RestoreBehavior, SigningTicket, TssClient};
use legacy_ios_workflows::{
    BasebandPolicy, CryptexPolicy, CryptexSource, DestructiveConsent, ExploitPolicy, NoncePolicy,
    PlanId, RestorePlan, RestorePlanError, RestoreRequest, RsepPolicy, SepPolicy, TicketPolicy,
};
use tracing::info;

use crate::{KitError, RestoreExecutionRequest, multipart::multipart_support, shsh::ShshRequest};

/// Signing ticket provenance of a powder restore. In every case the ticket
/// belongs to a base/latest version while the IPSW manifest is the target
/// version, like upstream's `shsh/<ecid>-<product>-<version>.shsh` copies.
#[derive(Clone, Debug)]
pub enum PowderTicketSource {
    /// Fetch the device's latest-version ticket from TSS using this
    /// latest-version IPSW's build identity, saving it under
    /// `destination_dir` in upstream's `<ecid>-<product>-<version>.shsh`
    /// layout (the version in the name is the target version, mirroring the
    /// wrapper copy in `restore_idevicerestore`). A4 only: those are the
    /// devices whose latest versions stay OTA-signed.
    FetchLatest {
        /// IPSW of the device's latest iOS version.
        firmware: PathBuf,
        /// Directory the fetched ticket is saved to.
        destination_dir: PathBuf,
        /// Device CPID (e.g. `0x8920`).
        chip_id: u64,
        /// Device BDID.
        board_id: u64,
    },
    /// User-supplied base-version SHSH blob. Required on A5/A5X/A6/A6X; on
    /// A4 it replaces the live TSS fetch (e.g. a blob saved earlier with
    /// `LegacyIosKit::save_shsh`).
    Provided(PathBuf),
}

/// Pwned-chain entry method of a powder restore, mirroring upstream's
/// kDFU/pwnDFU menu (`device_buttons`, restore.sh:6435-6474).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowderPwnMethod {
    /// The device enters kDFU mode beforehand (the jailbroken method, e.g.
    /// `LegacyIosKit::enter_kdfu`); the restore skips the exploit stage.
    Kdfu,
    /// Exploit the device in DFU mode: limera1n on A4, external checkm8-a5
    /// hardware on A5/A5X, and external litera1n-class tools on A6/A6X (the
    /// last two surface `ActionRequired` guidance while waiting, like
    /// upstream's pause at restore.sh:2257-2290).
    PwnDfu,
}

/// Request for a powder restore: drive a powdersn0w custom IPSW through the
/// restore engine with the ticket and pwned chain of the device class.
pub struct PowderRestoreRequest {
    device: DeviceIdentity,
    firmware: PathBuf,
    ticket: PowderTicketSource,
    pwn: PowderPwnMethod,
    baseband: BasebandPolicy,
}

impl PowderRestoreRequest {
    pub fn new(
        device: DeviceIdentity,
        firmware: impl Into<PathBuf>,
        ticket: PowderTicketSource,
        pwn: PowderPwnMethod,
    ) -> Self {
        Self {
            device,
            firmware: firmware.into(),
            ticket,
            pwn,
            baseband: BasebandPolicy::Auto,
        }
    }

    /// Baseband policy of the restore; powder builds with
    /// `--disable-bbupdate` should restore with [`BasebandPolicy::None`].
    pub fn with_baseband(mut self, policy: BasebandPolicy) -> Self {
        self.baseband = policy;
        self
    }
}

impl fmt::Debug for PowderRestoreRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowderRestoreRequest")
            .field("device", &self.device)
            .field("firmware", &self.firmware)
            .field("pwn", &self.pwn)
            .field("baseband", &self.baseband)
            .finish_non_exhaustive()
    }
}

/// A resolved powder restore: the validated inner restore plan plus the
/// resolved signing ticket, ready to execute.
pub struct PowderRestorePlan {
    inner: RestorePlan,
    ticket: SigningTicket,
    ticket_path: PathBuf,
    ticket_version: Option<IosVersion>,
    pwn: PowderPwnMethod,
    limera1n_payload: Option<Vec<u8>>,
}

impl PowderRestorePlan {
    /// Plan id binding the destructive consent.
    pub fn id(&self) -> &PlanId {
        self.inner.id()
    }

    pub const fn restore_plan(&self) -> &RestorePlan {
        &self.inner
    }

    /// Path of the signing ticket used for the restore (fetched or
    /// provided).
    pub fn ticket_path(&self) -> &std::path::Path {
        &self.ticket_path
    }

    /// Version the signing ticket was saved for; known only for a fetched
    /// latest-version ticket.
    pub const fn ticket_version(&self) -> Option<&IosVersion> {
        self.ticket_version.as_ref()
    }

    pub const fn pwn_method(&self) -> PowderPwnMethod {
        self.pwn
    }

    /// limera1n payload used when `PwnDfu` exploits an A4 device.
    pub fn with_limera1n_payload(mut self, payload: Vec<u8>) -> Self {
        self.limera1n_payload = Some(payload);
        self
    }

    pub fn confirm_destructive(&self) -> DestructiveConsent {
        self.inner.confirm_destructive()
    }

    /// Build the execution request; final verification stays on, as the
    /// single-stage powder restore boots the target system.
    pub(crate) fn into_execution_request(
        self,
        consent: DestructiveConsent,
        work_directory: impl Into<PathBuf>,
    ) -> RestoreExecutionRequest {
        let mut request =
            RestoreExecutionRequest::new(self.inner, consent, self.ticket, work_directory);
        if let Some(payload) = self.limera1n_payload {
            request = request.with_limera1n_payload(payload);
        }
        request
    }
}

impl fmt::Debug for PowderRestorePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowderRestorePlan")
            .field("inner", &self.inner)
            .field("ticket_path", &self.ticket_path)
            .field("ticket_version", &self.ticket_version)
            .field("pwn", &self.pwn)
            .finish_non_exhaustive()
    }
}

/// Resolve a powder restore plan: gate the device class and target version,
/// resolve the signing ticket per upstream's provenance rules, and plan the
/// restore with the pwned-chain exploit policy of the chosen entry method.
pub(crate) async fn plan(
    tss: &TssClient,
    request: PowderRestoreRequest,
) -> Result<PowderRestorePlan, KitError> {
    let profile = DeviceDatabase::bundled()
        .find_product(request.device.product_type())
        .ok_or_else(|| KitError::UnknownProduct(request.device.product_type().clone()))?;
    let soc = profile.soc();
    match soc {
        Soc::A4 | Soc::A5 | Soc::A5x | Soc::A6 | Soc::A6x => {}
        soc => {
            return Err(KitError::PowderRestoreUnsupportedDevice(format!(
                "{} ({soc})",
                request.device.product_type()
            )));
        }
    }

    let archive = FirmwareArchive::open(&request.firmware)?;
    let manifest = archive.build_manifest()?;
    let version = manifest.product_version().clone();

    // Upstream routes A4 powder targets 3.x/4.0-4.2.x through the two-stage
    // multipart flow (`restore_prepare`, restore.sh:6596-6616).
    if soc == Soc::A4 && multipart_support(request.device.product_type(), version.as_str()) {
        return Err(KitError::PowderRestoreRequiresMultipart(format!(
            "{} ({version})",
            request.device.product_type()
        )));
    }

    let (ticket, ticket_path, ticket_version) = match &request.ticket {
        PowderTicketSource::Provided(path) => (SigningTicket::open(path)?, path.clone(), None),
        PowderTicketSource::FetchLatest {
            firmware,
            destination_dir,
            chip_id,
            board_id,
        } => {
            if soc != Soc::A4 {
                return Err(KitError::PowderRestoreTicketFetchUnsupported(format!(
                    "{} ({soc})",
                    request.device.product_type()
                )));
            }
            let ecid = request
                .device
                .ecid()
                .ok_or(KitError::MissingDeviceSelector)?;
            let board_config = request
                .device
                .board_config()
                .ok_or(RestorePlanError::MissingBoardConfig)?;
            let destination = destination_dir.join(format!(
                "{ecid}-{}-{version}.shsh",
                request.device.product_type()
            ));
            info!(
                path = %destination.display(),
                "fetching the latest-version ticket for the powder restore"
            );
            let shsh = ShshRequest::new(
                firmware,
                board_config.clone(),
                RestoreBehavior::Erase,
                ecid,
                *board_id,
                *chip_id,
            );
            let summary = crate::shsh::save(tss, &shsh, &destination).await?;
            (
                SigningTicket::open(&destination)?,
                destination,
                Some(summary.product_version().clone()),
            )
        }
    };

    let exploit = match request.pwn {
        PowderPwnMethod::Kdfu => ExploitPolicy::AlreadyPwned,
        PowderPwnMethod::PwnDfu => ExploitPolicy::Auto,
    };
    let inner = RestorePlan::resolve(RestoreRequest {
        device: request.device,
        firmware: request.firmware,
        behavior: RestoreBehavior::Erase,
        ticket: TicketPolicy::Provided(ticket_path.clone()),
        baseband: request.baseband,
        sep: SepPolicy::Auto,
        rsep: RsepPolicy::Auto,
        cryptex: CryptexPolicy::Auto,
        cryptex_source: CryptexSource::Target,
        exploit,
        nonce: NoncePolicy::Manual,
    })?;

    Ok(PowderRestorePlan {
        inner,
        ticket,
        ticket_path,
        ticket_version,
        pwn: request.pwn,
        limera1n_payload: None,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::{BoardConfig, Ecid, ProductType};
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[tokio::test]
    async fn a4_restore_uses_the_provided_latest_blob() {
        let directory = tempfile::tempdir().unwrap();
        let ipsw = powder_ipsw("iPhone3,1", "n90ap", "7.1.2", "11D257");
        let ticket = ticket_blob(directory.path(), 42);
        let request = PowderRestoreRequest::new(
            device("iPhone3,1", "n90"),
            ipsw.path().to_owned(),
            PowderTicketSource::Provided(ticket.clone()),
            PowderPwnMethod::Kdfu,
        );

        let plan = plan(&TssClient::default(), request).await.unwrap();

        assert_eq!(plan.pwn_method(), PowderPwnMethod::Kdfu);
        assert_eq!(plan.ticket_path(), ticket);
        assert!(plan.ticket_version().is_none());
        assert_eq!(
            plan.restore_plan().exploit_policy(),
            ExploitPolicy::AlreadyPwned
        );
        assert!(matches!(
            plan.restore_plan().ticket_policy(),
            TicketPolicy::Provided(_)
        ));
    }

    #[tokio::test]
    async fn pwndfu_maps_to_the_automatic_exploit_policy() {
        let directory = tempfile::tempdir().unwrap();
        let ipsw = powder_ipsw("iPhone3,1", "n90ap", "7.1.2", "11D257");
        let ticket = ticket_blob(directory.path(), 42);
        let request = PowderRestoreRequest::new(
            device("iPhone3,1", "n90"),
            ipsw.path().to_owned(),
            PowderTicketSource::Provided(ticket),
            PowderPwnMethod::PwnDfu,
        );

        let plan = plan(&TssClient::default(), request).await.unwrap();

        assert_eq!(plan.restore_plan().exploit_policy(), ExploitPolicy::Auto);
    }

    #[tokio::test]
    async fn a4_multipart_targets_are_redirected() {
        let directory = tempfile::tempdir().unwrap();
        let ipsw = powder_ipsw("iPhone3,1", "n90ap", "4.2.1", "8C148");
        let ticket = ticket_blob(directory.path(), 42);
        let request = PowderRestoreRequest::new(
            device("iPhone3,1", "n90"),
            ipsw.path().to_owned(),
            PowderTicketSource::Provided(ticket),
            PowderPwnMethod::PwnDfu,
        );

        let error = plan(&TssClient::default(), request).await.unwrap_err();

        assert!(
            matches!(error, KitError::PowderRestoreRequiresMultipart(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a5_cannot_fetch_a_latest_version_ticket() {
        let ipsw = powder_ipsw("iPhone4,1", "n94ap", "6.1.3", "10B329");
        let request = PowderRestoreRequest::new(
            device("iPhone4,1", "n94"),
            ipsw.path().to_owned(),
            PowderTicketSource::FetchLatest {
                firmware: PathBuf::from("unused.ipsw"),
                destination_dir: PathBuf::from("unused"),
                chip_id: 0x8940,
                board_id: 0,
            },
            PowderPwnMethod::Kdfu,
        );

        let error = plan(&TssClient::default(), request).await.unwrap_err();

        assert!(
            matches!(error, KitError::PowderRestoreTicketFetchUnsupported(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn non_powder_devices_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let ipsw = powder_ipsw("iPhone2,1", "n88ap", "4.2.1", "8C148");
        let ticket = ticket_blob(directory.path(), 42);
        let request = PowderRestoreRequest::new(
            device("iPhone2,1", "n88"),
            ipsw.path().to_owned(),
            PowderTicketSource::Provided(ticket),
            PowderPwnMethod::PwnDfu,
        );

        let error = plan(&TssClient::default(), request).await.unwrap_err();

        assert!(
            matches!(error, KitError::PowderRestoreUnsupportedDevice(_)),
            "{error}"
        );
    }

    fn device(product: &str, board: &str) -> DeviceIdentity {
        DeviceIdentity::new(ProductType::from(product), Soc::A4)
            .with_board_config(BoardConfig::from(board))
            .with_ecid(Ecid::new(42))
    }

    fn powder_ipsw(product: &str, device_class: &str, version: &str, build: &str) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>{version}</string>
<key>ProductBuildVersion</key><string>{build}</string>
<key>SupportedProductTypes</key><array><string>{product}</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>{device_class}</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict></dict>
</dict></array>
</dict></plist>"#
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
        file
    }

    fn ticket_blob(directory: &std::path::Path, ecid: u64) -> PathBuf {
        let path = directory.join("ticket.shsh");
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("APTicket".to_owned(), plist::Value::Data(vec![0x30, 0x82]));
        dictionary.insert("ApECID".to_owned(), plist::Value::Integer(ecid.into()));
        plist::to_file_xml(&path, &plist::Value::Dictionary(dictionary)).unwrap();
        path
    }
}
