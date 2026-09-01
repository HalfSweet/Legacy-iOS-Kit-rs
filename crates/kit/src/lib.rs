#![forbid(unsafe_code)]

//! Public facade for embedding Legacy iOS Kit workflows.

mod alloc8;
mod baseband;
mod bootstrap;
mod classic;
mod device;
mod erase;
mod error;
mod exploit;
mod firmware;
mod fourthree;
mod gilbertjb;
mod hacktivate;
mod hfs;
mod image_payload;
mod jailbreak;
mod kdfu;
mod lease;
mod multipart;
mod operation;
mod pairing;
mod powder;
mod powder_restore;
mod pwnage;
mod ramdisk;
mod ramdisk_boot;
mod recovery;
mod restore_execution;
mod shsh;
pub mod signing;
mod trollrestore;
mod trollstore;

pub use bootstrap::{
    BootstrapPackages, BootstrapSelection, bootstrap_selection, gunzip, select_untether7,
};
pub use classic::{ClassicPreparePlan, ClassicPrepareRequest, DEFAULT_CLASSIC_RAMDISK_GROW_BLOCKS};
pub use device::{
    BackendFailure, DeviceDiagnostics, DeviceInventory, DeviceManager, DeviceSummary,
};
pub use erase::{EraseConsent, ErasePlan};
pub use error::KitError;
pub use firmware::{
    CustomRootfsRequest, FirmwareIdentitySummary, FirmwareSummary, RemoteFirmwareSummary,
};
pub use fourthree::{
    FOURTHREE_BASE_VERSIONS, FOURTHREE_BOOTCHAIN_BUILD, FOURTHREE_BOOTCHAIN_VERSION,
    FOURTHREE_TARGET_VERSION, FourThreeComponentSource, FourThreeOpenSsh, FourThreePatch,
    FourThreePrepareOutcome, FourThreePrepareRequest, FourThreeStep, FourThreeStep3Packages,
    TwistedMind2Output, fourthree_board_config, fourthree_data_partition_bytes,
    fourthree_lockdownd_patch_id, fourthree_patch_id, point_restore_device_tree_at_downgrade,
};
pub use gilbertjb::{GilbertJbConsent, GilbertJbPlan, gilbertjb_support};
pub use hacktivate::{HacktivateMethod, hacktivate_method};
pub use hfs::{HfsEntrySummary, HfsKind, HfsMutation, HfsStatSummary};
pub use image_payload::{ImageCipher, ImageCipherError};
pub use jailbreak::{FstabReplacement, JailbreakPackages, JailbreakPlan, UntetherPackage};
pub use kdfu::{prepare_pwned_ibss, select_kloader};
pub use lease::DeviceLease;
pub use legacy_ios_assets::{Redistribution, ResourceId, ResourceRecord};
pub use legacy_ios_core::{
    BoardConfig, BootNonce, BuildId, Capability, CapabilitySet, ConnectionId, DeviceIdentity,
    DeviceMode, DeviceSelector, DeviceSnapshot, Ecid, IosVersion, OperationEvent, OperationId,
    OperationOutcome, ProductType, Recoverability, Soc, Udid,
};
pub use legacy_ios_firmware::{RestoreBehavior, SigningTicket, TicketError};
pub use legacy_ios_image::{
    BootMode, BootPartition, DmgError, DmgFirmwareKey, Iboot32PatchOptions,
};
pub use legacy_ios_services::{
    ActivationState, AfcPath, AfcPathError, AppFilter, BackupOptions, BackupOutcome,
    BackupPassword, BackupRestoreOptions, DeviceFileInfo, DeviceFileKind, DeviceFiles,
    DeviceStorageInfo, DeviceSyslog, HostKeyPolicy, InstalledApp, MountError, MountGuard,
    MountOptions, NormalBackend, RamdiskSsh, ScpPath, ScpPathError, SshCommandOutput, SshPassword,
    SshTarget, tar_contains_entry, tar_extract_entry,
};
pub use legacy_ios_transport::{
    HostRequirement, HostRequirementCode, RecoveryDeviceInfo, UsbAccess, UsbHostDevice,
    UsbHostDiagnostics,
};
pub use legacy_ios_workflows::{
    BasebandPolicy, DestructiveConsent, ExploitPolicy, NoncePolicy, PlanId, RamdiskBootComponent,
    RamdiskBootPlan, RamdiskBootPlanError, RamdiskBootPlanStep, RamdiskBootRequest,
    RamdiskBootStepKind, RestoreComponent, RestorePlan, RestorePlanError, RestoreRequest,
    RestoreStep, RestoreStepKind, SepPolicy, TicketPolicy,
};
pub use multipart::{
    MULTIPART_IBOOT_BOOT_ARGS, MULTIPART_IBOOT_BOOT_ARGS_VERBOSE, MULTIPART_NOR_BUILD,
    MULTIPART_NOR_VERSION, MultipartIpswSummary, MultipartPrepareRequest, MultipartRestoreRequest,
    NorSource, RamdiskPayload, TargetIbootDisposition, extract_apticket_der,
    multipart_base_version, multipart_support, ramdisk_payload, reboot4_resource,
    target_iboot_disposition, target_iboot_patch_options,
};
pub use operation::OperationHandle;
pub use pairing::PairingStore;
pub use powder::{
    DEFAULT_RAMDISK_GROW_BLOCKS, PowderBasePlan, PowderPreparePlan, PowderPrepareRequest,
};
pub use powder_restore::{
    PowderPwnMethod, PowderRestorePlan, PowderRestoreRequest, PowderTicketSource,
};
pub use ramdisk::{RamdiskBuildRequest, RamdiskBuildSummary};
pub use ramdisk_boot::RamdiskBootExecutionRequest;
pub use recovery::{RecoveryDevice, RecoveryManager, RecoveryUploadResult};
pub use restore_execution::RestoreExecutionRequest;
pub use shsh::{ShshRequest, ShshSummary};
pub use signing::{AppSignOutcome, AppSignRequest};
pub use trollrestore::{
    DEFAULT_APP as TROLLRESTORE_DEFAULT_APP, TrollRestoreConsent, TrollRestorePlan,
    trollrestore_support,
};

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

    pub fn with_normal_backend(mut self, backend: NormalBackend) -> Self {
        self.devices.set_normal_backend(backend);
        self
    }

    pub fn with_pairing_store(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.devices = self.devices.with_pairing_store(PairingStore::new(root));
        self
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

    pub async fn decrypt_firmware_dmg(
        &self,
        source: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        key: DmgFirmwareKey,
    ) -> Result<(), KitError> {
        firmware::decrypt_dmg(source.into(), destination.into(), key).await
    }

    pub async fn fetch_resource(
        &self,
        id: &ResourceId,
        cache_root: impl Into<std::path::PathBuf>,
    ) -> Result<std::path::PathBuf, KitError> {
        firmware::fetch_resource(id, cache_root.into()).await
    }

    pub async fn list_hfs(
        &self,
        image: impl Into<std::path::PathBuf>,
        path: impl Into<String>,
    ) -> Result<Vec<HfsEntrySummary>, KitError> {
        hfs::list(image.into(), path.into()).await
    }

    pub async fn stat_hfs(
        &self,
        image: impl Into<std::path::PathBuf>,
        path: impl Into<String>,
    ) -> Result<HfsStatSummary, KitError> {
        hfs::stat(image.into(), path.into()).await
    }

    pub async fn extract_hfs_file(
        &self,
        image: impl Into<std::path::PathBuf>,
        path: impl Into<String>,
        destination: impl Into<std::path::PathBuf>,
    ) -> Result<(), KitError> {
        hfs::extract(image.into(), path.into(), destination.into()).await
    }

    pub async fn edit_hfs(
        &self,
        source: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        mutations: Vec<HfsMutation>,
    ) -> Result<(), KitError> {
        hfs::edit(source.into(), destination.into(), mutations).await
    }

    pub async fn build_custom_rootfs_ipsw(
        &self,
        request: CustomRootfsRequest,
    ) -> Result<FirmwareSummary, KitError> {
        firmware::build_custom_rootfs(request).await
    }

    pub async fn build_ramdisk(
        &self,
        request: RamdiskBuildRequest,
    ) -> Result<RamdiskBuildSummary, KitError> {
        ramdisk::build(request).await
    }

    pub async fn extract_image_payload(
        &self,
        source: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        cipher: Option<ImageCipher>,
    ) -> Result<(), KitError> {
        image_payload::extract(source.into(), destination.into(), cipher).await
    }

    pub async fn replace_image_payload(
        &self,
        source: impl Into<std::path::PathBuf>,
        payload: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        cipher: Option<ImageCipher>,
    ) -> Result<(), KitError> {
        image_payload::replace(source.into(), payload.into(), destination.into(), cipher).await
    }

    /// Patch a decrypted 32-bit iBoot/iBSS/iBEC image with the selected
    /// iBoot32Patcher options (the RSA check patch is always applied).
    pub async fn patch_iboot32(
        &self,
        source: impl Into<std::path::PathBuf>,
        destination: impl Into<std::path::PathBuf>,
        options: Iboot32PatchOptions,
    ) -> Result<(), KitError> {
        image_payload::patch_iboot32(source.into(), destination.into(), options).await
    }

    pub fn convert_onboard_dump(&self, dump: &[u8]) -> Result<SigningTicket, KitError> {
        // Raw dumps from powdersn0w/DRA downgraded devices carry the mangled
        // `ibob` LLB magic; rewrite it to `blli` like upstream's
        // shsh_convert_onboard before looking for the ticket.
        let fixed = legacy_ios_image::rewrite_ibob_magic(dump);
        let dump = fixed.as_deref().unwrap_or(dump);
        if fixed.is_some() {
            tracing::info!("rewrote the ibob ticket magic of the onboard dump");
        }
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

    pub fn plan_ramdisk_boot(
        &self,
        request: RamdiskBootRequest,
    ) -> Result<RamdiskBootPlan, KitError> {
        Ok(RamdiskBootPlan::resolve(request)?)
    }

    pub fn execute_ramdisk_boot(&self, request: RamdiskBootExecutionRequest) -> OperationHandle {
        ramdisk_boot::spawn(self.leases.clone(), request)
    }

    pub fn execute_restore(&self, request: RestoreExecutionRequest) -> OperationHandle {
        restore_execution::spawn(
            self.devices.clone(),
            self.leases.clone(),
            self.tss.clone(),
            request,
        )
    }

    /// Build the two custom IPSWs of an iOS 3.x/4.x multipart restore:
    /// the iOS 5.1.1-based NOR flash IPSW (part 1) and the multipatched
    /// target IPSW (part 2).
    pub async fn prepare_multipart_ipsw(
        &self,
        request: MultipartPrepareRequest,
    ) -> Result<MultipartIpswSummary, KitError> {
        multipart::prepare(request).await
    }

    /// Plan a powdersn0w custom build: gate the device and version, resolve
    /// the firmware bundle/config/payload plan, and fetch the payload
    /// resources. Without a base IPSW this mirrors upstream's
    /// `ipsw_prepare_32bit`; with one, the two-bundle `ipsw_prepare_powder`
    /// (or, for a 4.3.x target with `-apticket`, `ipsw_prepare_ios4powder`).
    pub async fn plan_powder_ipsw(
        &self,
        request: PowderPrepareRequest,
    ) -> Result<PowderPreparePlan, KitError> {
        powder::plan(request).await
    }

    /// Execute a powder plan: personalize the boot chain, root filesystem,
    /// and restore ramdisk, then write the custom IPSW, reporting progress
    /// over the returned handle.
    pub fn execute_powder_prepare(&self, plan: PowderPreparePlan) -> OperationHandle {
        powder::spawn(plan)
    }

    /// Plan a classic custom build for old devices (S5L8900 and
    /// S5L8720/8920/8922/A4), mirroring upstream's `ipsw_prepare_jailbreak`
    /// with the classic xpwn `ipsw` tool: gate the device and the
    /// hacktivation request, derive old mode, resolve the firmware bundle and
    /// payload plan, and fetch the patch/payload resources.
    pub async fn plan_classic_ipsw(
        &self,
        request: ClassicPrepareRequest,
    ) -> Result<ClassicPreparePlan, KitError> {
        classic::plan(request).await
    }

    /// Execute a classic plan: patch and decrypt the boot chain, personalize
    /// the root filesystem and restore ramdisk, then write the custom IPSW,
    /// reporting progress over the returned handle.
    pub fn execute_classic_prepare(&self, plan: ClassicPreparePlan) -> OperationHandle {
        classic::spawn(plan)
    }

    /// Execute a two-stage multipart restore: part 1 (NOR flash) without
    /// final verification, then part 2 after the device re-enters
    /// DFU/recovery.
    pub fn execute_multipart_restore(&self, request: MultipartRestoreRequest) -> OperationHandle {
        multipart::spawn(
            self.devices.clone(),
            self.leases.clone(),
            self.tss.clone(),
            request,
        )
    }

    /// Plan a powder restore: gate the device class, resolve the signing
    /// ticket per upstream's provenance rules (a live latest-version TSS
    /// fetch on A4, a provided base-version blob elsewhere), and plan the
    /// restore with the pwned-chain exploit policy of the entry method.
    pub async fn plan_powder_restore(
        &self,
        request: PowderRestoreRequest,
    ) -> Result<PowderRestorePlan, KitError> {
        powder_restore::plan(&self.tss, request).await
    }

    /// Execute a powder restore with final verification on.
    pub fn execute_powder_restore(
        &self,
        plan: PowderRestorePlan,
        consent: DestructiveConsent,
        work_directory: impl Into<std::path::PathBuf>,
    ) -> OperationHandle {
        restore_execution::spawn(
            self.devices.clone(),
            self.leases.clone(),
            self.tss.clone(),
            plan.into_execution_request(consent, work_directory),
        )
    }

    /// Upload kloader and a pwned iBSS over SSH and wait for kDFU mode.
    pub async fn enter_kdfu(
        &self,
        ssh: &RamdiskSsh,
        kloader: &[u8],
        pwned_ibss: &[u8],
        ecid: Option<Ecid>,
    ) -> Result<(), KitError> {
        kdfu::enter_kdfu(ssh, kloader, pwned_ibss).await?;
        kdfu::await_kdfu(ecid).await
    }

    /// Hacktivate a jailbroken device over SSH.
    pub async fn hacktivate(
        &self,
        ssh: &RamdiskSsh,
        method: &HacktivateMethod,
        patch: Option<&[u8]>,
    ) -> Result<(), KitError> {
        hacktivate::hacktivate(ssh, method, patch).await
    }

    /// Revert hacktivation by restoring the original lockdownd.
    pub async fn revert_hacktivate(
        &self,
        ssh: &RamdiskSsh,
        original: Option<&[u8]>,
    ) -> Result<(), KitError> {
        hacktivate::revert_hacktivate(ssh, original).await
    }

    /// Query the highest completed FourThree step on the device.
    pub async fn fourthree_check(&self, ssh: &RamdiskSsh) -> Result<FourThreeStep, KitError> {
        fourthree::check(ssh).await
    }

    /// FourThree step 1: build the custom 6.1.3 IPSW and the patched 4.3.x
    /// dualboot components (kernelcache, LLB, RootFS) from the stock IPSWs.
    pub async fn prepare_fourthree_ipsw(
        &self,
        request: FourThreePrepareRequest,
    ) -> Result<FourThreePrepareOutcome, KitError> {
        fourthree::prepare(request).await
    }

    /// FourThree step 2: install the dualboot packages and partition the
    /// device with TwistedMind2. Returns the generated /TwistedMind2* files.
    pub async fn fourthree_step2(
        &self,
        ssh: &RamdiskSsh,
        dualbootstuff: &[u8],
        size_gb: u32,
    ) -> Result<Vec<TwistedMind2Output>, KitError> {
        fourthree::step2(ssh, dualbootstuff, size_gb).await
    }

    /// FourThree step 3: create the 4.3.x filesystems, restore the rootfs,
    /// jailbreak it, and install the dualboot kernelcache and LLB.
    pub async fn fourthree_step3(
        &self,
        ssh: &RamdiskSsh,
        product_type: &str,
        packages: &FourThreeStep3Packages,
    ) -> Result<(), KitError> {
        fourthree::step3(ssh, product_type, packages).await
    }

    /// Install the FourThree companion app on the 6.1.3 system.
    pub async fn fourthree_install_app(
        &self,
        ssh: &RamdiskSsh,
        app: &[u8],
    ) -> Result<(), KitError> {
        fourthree::install_app(ssh, app).await
    }

    /// Boot the 4.3.x system through the FourThree app. The kloader drops the
    /// SSH session.
    pub async fn fourthree_boot(&self, ssh: &RamdiskSsh) -> Result<(), KitError> {
        fourthree::boot(ssh).await
    }

    /// Install the Cydia bootstrap on a 64-bit iOS 7/8/9 device from an SSH
    /// ramdisk session.
    pub async fn install_bootstrap(
        &self,
        ssh: &RamdiskSsh,
        version: &str,
        packages: &BootstrapPackages,
    ) -> Result<(), KitError> {
        bootstrap::install_bootstrap(ssh, version, packages).await
    }

    /// Install an iOS 7 untether package from an SSH ramdisk session.
    pub async fn install_untether7(
        &self,
        ssh: &RamdiskSsh,
        untether: &[u8],
        stash: bool,
    ) -> Result<(), KitError> {
        bootstrap::install_untether7(ssh, untether, stash).await
    }

    /// Install the 32-bit jailbreak from an SSH ramdisk session, mirroring
    /// upstream's `device_ramdisk jailbreak` flow.
    pub async fn install_jailbreak(
        &self,
        ssh: &RamdiskSsh,
        plan: &JailbreakPlan,
        packages: &JailbreakPackages,
    ) -> Result<(), KitError> {
        jailbreak::install_jailbreak(ssh, plan, packages).await
    }

    /// Install the TrollStore persistence helper into the Tips app from an
    /// SSH ramdisk session.
    pub async fn install_trollstore(
        &self,
        ssh: &RamdiskSsh,
        persistence_helper: &[u8],
        helper: &[u8],
    ) -> Result<(), KitError> {
        trollstore::install_trollstore(ssh, persistence_helper, helper).await
    }

    /// Exploit an S5L8900 device in DFU mode with the Pwnage 2.0 WTF image.
    pub async fn pwn_wtf(
        &self,
        ecid: Option<Ecid>,
        cache_root: impl Into<std::path::PathBuf>,
    ) -> Result<(), KitError> {
        pwnage::pwn_wtf(ecid, cache_root.into()).await
    }

    /// Install the alloc8 exploit to the NOR of a new-bootrom iPhone 3GS.
    /// This permanently modifies the device NOR and requires a prior custom
    /// 24Kpwn restore; when the device is not already in pwned DFU mode, a
    /// limera1n payload must be provided.
    pub async fn install_alloc8(
        &self,
        ecid: Option<Ecid>,
        limera1n_payload: Option<Vec<u8>>,
        cache_root: impl Into<std::path::PathBuf>,
    ) -> Result<(), KitError> {
        alloc8::install_alloc8(ecid, limera1n_payload, cache_root.into()).await
    }

    pub async fn plan_erase(&self, udid: Udid) -> Result<ErasePlan, KitError> {
        self.devices.ensure_normal(&udid).await?;
        Ok(ErasePlan::new(udid))
    }

    /// Plan a TrollRestore installation: gate the device version, resolve the
    /// removable system app to replace, and produce a consent-ready plan.
    pub async fn plan_trollrestore(
        &self,
        udid: Udid,
        app: &str,
    ) -> Result<TrollRestorePlan, KitError> {
        trollrestore::plan(&self.devices, udid, app).await
    }

    /// Plan a g1lbertJB jailbreak: gate the device and build to the A5 iOS
    /// 5.0-5.1.1 set and refuse unactivated, backup-encrypted, or already
    /// jailbroken devices.
    pub async fn plan_gilbertjb(&self, udid: Udid) -> Result<GilbertJbPlan, KitError> {
        gilbertjb::plan(&self.devices, udid).await
    }

    /// Run the g1lbertJB jailbreak over AFC/file_relay/mobilebackup2. The
    /// operation reboots the device once, asks the user to run the g1lbertJB
    /// home-screen icon via an `ActionRequired` event, and restarts the
    /// device when done.
    pub fn execute_gilbertjb(
        &self,
        plan: GilbertJbPlan,
        consent: GilbertJbConsent,
        cache_root: impl Into<std::path::PathBuf>,
        work_directory: impl Into<std::path::PathBuf>,
    ) -> OperationHandle {
        gilbertjb::spawn(
            self.devices.clone(),
            self.leases.clone(),
            plan,
            consent,
            cache_root.into(),
            work_directory.into(),
        )
    }

    /// Install the TrollStore persistence helper over the planned system app
    /// via the sparserestore exploit, then reboot the device.
    pub fn execute_trollrestore(
        &self,
        plan: TrollRestorePlan,
        consent: TrollRestoreConsent,
        cache_root: impl Into<std::path::PathBuf>,
        work_directory: impl Into<std::path::PathBuf>,
    ) -> OperationHandle {
        trollrestore::spawn(
            self.devices.clone(),
            self.leases.clone(),
            plan,
            consent,
            cache_root.into(),
            work_directory.into(),
        )
    }

    pub fn execute_erase(
        &self,
        plan: ErasePlan,
        consent: EraseConsent,
        work_directory: impl Into<std::path::PathBuf>,
    ) -> OperationHandle {
        erase::spawn(
            self.devices.clone(),
            self.leases.clone(),
            plan,
            consent,
            work_directory.into(),
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
