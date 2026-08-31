#![forbid(unsafe_code)]

//! Public facade for embedding Legacy iOS Kit workflows.

mod device;
mod error;
mod firmware;
mod lease;
mod operation;
mod recovery;
mod restore_execution;
mod shsh;

pub use device::{
    BackendFailure, DeviceDiagnostics, DeviceInventory, DeviceManager, DeviceSummary,
};
pub use error::KitError;
pub use firmware::{FirmwareIdentitySummary, FirmwareSummary, RemoteFirmwareSummary};
pub use lease::DeviceLease;
pub use legacy_ios_core::{
    BoardConfig, BuildId, Capability, CapabilitySet, ConnectionId, DeviceIdentity, DeviceMode,
    DeviceSelector, DeviceSnapshot, Ecid, IosVersion, OperationEvent, OperationId,
    OperationOutcome, ProductType, Recoverability, Soc, Udid,
};
pub use legacy_ios_firmware::{RestoreBehavior, SigningTicket, TicketError};
pub use legacy_ios_services::{
    ActivationState, AfcPath, AfcPathError, AppFilter, BackupOptions, BackupOutcome,
    BackupRestoreOptions, DeviceFileInfo, DeviceFileKind, DeviceFiles, DeviceStorageInfo,
    DeviceSyslog, HostKeyPolicy, InstalledApp, RamdiskSsh, ScpPath, ScpPathError, SshCommandOutput,
    SshPassword, SshTarget,
};
pub use legacy_ios_transport::RecoveryDeviceInfo;
pub use legacy_ios_workflows::{
    BasebandPolicy, DestructiveConsent, ExploitPolicy, PlanId, RestoreComponent, RestorePlan,
    RestorePlanError, RestoreRequest, RestoreStep, RestoreStepKind, SepPolicy, TicketPolicy,
};
pub use operation::OperationHandle;
pub use recovery::{RecoveryDevice, RecoveryManager, RecoveryUploadResult};
pub use restore_execution::RestoreExecutionRequest;
pub use shsh::{ShshRequest, ShshSummary};

#[derive(Clone, Debug, Default)]
pub struct LegacyIosKit {
    devices: DeviceManager,
    recovery: RecoveryManager,
    leases: lease::DeviceLeaseRegistry,
    tss: legacy_ios_firmware::TssClient,
}

impl LegacyIosKit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &DeviceManager {
        &self.devices
    }

    pub fn recovery(&self) -> &RecoveryManager {
        &self.recovery
    }

    pub fn with_tss_endpoint(mut self, endpoint: &str) -> Result<Self, KitError> {
        self.tss = legacy_ios_firmware::TssClient::with_endpoint_str(endpoint)?;
        Ok(self)
    }

    pub async fn lease_device(&self, device: &DeviceIdentity) -> Result<DeviceLease, KitError> {
        let selector = device.selector().ok_or(KitError::MissingDeviceSelector)?;
        Ok(self.leases.acquire(selector).await)
    }

    pub fn inspect_firmware(
        &self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<FirmwareSummary, KitError> {
        FirmwareSummary::inspect(path.into())
    }

    pub async fn inspect_remote_firmware(
        &self,
        url: impl Into<String>,
    ) -> Result<RemoteFirmwareSummary, KitError> {
        RemoteFirmwareSummary::inspect(url.into()).await
    }

    pub async fn build_custom_ipsw(
        &self,
        source: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        replacements: Vec<(String, Vec<u8>)>,
        removals: Vec<String>,
    ) -> Result<FirmwareSummary, KitError> {
        let source = legacy_ios_firmware::FirmwareArchive::open(source.into())?;
        let mut builder = legacy_ios_firmware::CustomIpswBuilder::new(source);
        for (name, data) in replacements {
            builder = builder.replace(name, data)?;
        }
        for name in removals {
            builder = builder.remove(name)?;
        }
        let destination = destination.into();
        builder.build(&destination).await?;
        FirmwareSummary::inspect(destination)
    }

    pub fn convert_onboard_dump(&self, dump: &[u8]) -> Result<SigningTicket, KitError> {
        let ticket = legacy_ios_image::OnboardTicket::parse(dump)?;
        Ok(SigningTicket::from_img4_ticket(
            ticket.im4m().to_vec(),
            ticket.generator().map(ToOwned::to_owned),
        )?)
    }

    pub fn resolve_device_identity(
        &self,
        product_type: ProductType,
        board_config: BoardConfig,
    ) -> Result<DeviceIdentity, KitError> {
        let profile = legacy_ios_assets::DeviceDatabase::bundled()
            .find_product(&product_type)
            .ok_or_else(|| KitError::UnknownProduct(product_type.clone()))?;
        if !profile.board_configs().contains(&board_config) {
            return Err(KitError::UnknownBoardConfig {
                product_type,
                board_config,
            });
        }
        Ok(DeviceIdentity::new(product_type, profile.soc()).with_board_config(board_config))
    }

    pub fn plan_restore(&self, request: RestoreRequest) -> Result<RestorePlan, KitError> {
        Ok(RestorePlan::resolve(request)?)
    }

    pub fn execute_restore(&self, request: RestoreExecutionRequest) -> OperationHandle {
        restore_execution::spawn(
            self.devices.clone(),
            self.leases.clone(),
            self.tss.clone(),
            request,
        )
    }

    pub async fn save_shsh(
        &self,
        request: &ShshRequest,
        destination: impl AsRef<std::path::Path>,
    ) -> Result<ShshSummary, KitError> {
        shsh::save(&self.tss, request, destination.as_ref()).await
    }
}
