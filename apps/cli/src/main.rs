#![forbid(unsafe_code)]

mod config;

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use legacy_ios_kit::{
    ActivationState, AfcPath, AppFilter, AppSignRequest, BackupOptions, BackupOutcome,
    BackupPassword, BackupRestoreOptions, BasebandPolicy, BoardConfig, BootMode, BootNonce,
    BootPartition, ClassicPrepareRequest, CustomRootfsRequest, DeviceDiagnostics, DeviceFileInfo,
    DeviceInventory, DeviceStorageInfo, DeviceSummary, DmgFirmwareKey, Ecid, ExploitPolicy,
    FirmwareSummary, FourThreeComponentSource, FourThreePrepareRequest, HfsEntrySummary,
    HfsMutation, HfsStatSummary, HostKeyPolicy, Iboot32PatchOptions, ImageCipher, InstalledApp,
    IosVersion, LegacyIosKit, MountOptions, MultipartPrepareRequest, MultipartRestoreRequest,
    NoncePolicy, NorSource, OperationEvent, OperationHandle, OperationOutcome,
    PowderPrepareRequest, PowderPwnMethod, PowderRestoreRequest, PowderTicketSource, ProductType,
    RamdiskBootExecutionRequest, RamdiskBootRequest, RamdiskBuildRequest, RamdiskBuildSummary,
    RamdiskSsh, RecoveryDeviceInfo, RecoveryUploadResult, RemoteFirmwareSummary, ResourceId,
    RestoreBehavior, RestoreExecutionRequest, RestorePlan, RestoreRequest, ScpPath, SepPolicy,
    ShshRequest, ShshSummary, SigningTicket, Soc, SshCommandOutput, SshPassword, SshTarget,
    TicketPolicy, Udid, UsbHostDiagnostics, extract_apticket_der,
};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use config::AppConfig;

#[derive(Debug, Parser)]
#[command(name = "lik", version, about = "Pure-Rust legacy iOS device toolkit")]
struct Cli {
    #[arg(long, value_enum, global = true)]
    output: Option<OutputFormat>,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(short, long, action = ArgAction::Count, global = true, conflicts_with = "quiet")]
    verbose: u8,
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Data {
        #[command(subcommand)]
        command: DataCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Firmware {
        #[command(subcommand)]
        command: FirmwareCommand,
    },
    Ramdisk {
        #[command(subcommand)]
        command: RamdiskCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
    Shsh {
        #[command(subcommand)]
        command: ShshCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RamdiskCommand {
    /// Boot an SSH ramdisk on a pwned DFU or Recovery mode device.
    Boot {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        #[arg(long)]
        ibss: PathBuf,
        #[arg(long)]
        ibec: Option<PathBuf>,
        /// RestoreRamDisk image; omit to just boot the kernel tethered.
        #[arg(long)]
        ramdisk: Option<PathBuf>,
        #[arg(long)]
        device_tree: PathBuf,
        #[arg(long)]
        trust_cache: Option<PathBuf>,
        #[arg(long)]
        kernel: PathBuf,
        #[arg(long)]
        ticket: Option<PathBuf>,
        #[arg(long)]
        boot_args: Option<String>,
        #[arg(long, value_enum, default_value_t = ExploitArg::AlreadyPwned)]
        exploit: ExploitArg,
        #[arg(long)]
        limera1n_payload: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Build a patched RestoreRamDisk component from an IPSW identity.
    Build {
        firmware: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long, value_enum, default_value_t = RestoreBehaviorArg::Erase)]
        behavior: RestoreBehaviorArg,
        #[arg(long, requires = "iv")]
        key: Option<String>,
        #[arg(long, requires = "key")]
        iv: Option<String>,
        #[arg(long)]
        grow: Option<usize>,
        #[arg(long = "add", value_name = "HFS_PATH=FILE")]
        additions: Vec<String>,
        #[arg(long = "remove", value_name = "HFS_PATH")]
        removals: Vec<String>,
        #[arg(long)]
        recursive: bool,
        #[arg(long = "tar", value_name = "ARCHIVE")]
        archives: Vec<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Execute a command over SSH through the system USB mux.
    Ssh {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Copy a host file into the ramdisk over SCP.
    Push {
        source: PathBuf,
        destination: ScpPath,
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Copy a ramdisk file to the host over SCP.
    Pull {
        source: ScpPath,
        destination: PathBuf,
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long, default_value_t = 1024 * 1024 * 1024)]
        max_size: u64,
    },
    /// Dump and convert the onboard IMG4 signing ticket.
    DumpOnboard {
        destination: PathBuf,
        #[arg(long, default_value = "/dev/rdisk1")]
        disk: ScpPath,
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
    },
    /// Dump activation records from the mounted data partition.
    DumpActivation {
        destination: PathBuf,
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        /// Device iOS version; read from the mounted rootfs when omitted.
        #[arg(long)]
        ios_version: Option<String>,
    },
    /// Dump baseband firmware from the mounted root filesystem.
    DumpBaseband {
        destination: PathBuf,
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
    },
    /// Install TrollStore into the Tips app from an SSH ramdisk (iOS 14/15).
    Trollstore {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Clear all NVRAM variables on the device.
    NvramClear {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Set the device clock to the host time.
    FixDatetime {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
    },
    /// Trigger erase-all-content-and-settings on an iOS 9+ device.
    Erase9 {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Perform the erase-all-content-and-settings procedure on iOS 7/8.
    Erase78 {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Install the Cydia bootstrap on a 64-bit iOS 7/8/9 device.
    Bootstrap {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        /// Device iOS version; read from the mounted rootfs when omitted.
        #[arg(long)]
        ios_version: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Install the iOS 7 untether package matching the device version.
    Untether7 {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        /// Device iOS version; read from the mounted rootfs when omitted.
        #[arg(long)]
        ios_version: Option<String>,
        /// Let Cydia stash components to the data partition on first run.
        #[arg(long)]
        stash: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Jailbreak a 32-bit device from an SSH ramdisk.
    Jailbreak {
        #[arg(long)]
        device_id: Option<u32>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        /// Device product type, e.g. iPhone3,1.
        #[arg(long)]
        device: ProductType,
        /// Device iOS version; read from the mounted rootfs when omitted.
        #[arg(long)]
        ios_version: Option<String>,
        /// Device iOS build; read from the mounted rootfs when omitted.
        #[arg(long)]
        build: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DataCommand {
    /// Create a mobilebackup2 backup in a host directory.
    Backup {
        udid: Udid,
        destination: PathBuf,
        #[arg(long)]
        full: bool,
    },
    /// Restore a mobilebackup2 backup to a device.
    Restore {
        udid: Udid,
        root: PathBuf,
        source_identifier: String,
        #[arg(long)]
        no_reboot: bool,
        #[arg(long)]
        replace_settings: bool,
        #[arg(long)]
        system_files: bool,
        #[arg(long)]
        remove_missing: bool,
        #[arg(long)]
        password: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Enable, change, or disable device backup encryption.
    Encryption {
        udid: Udid,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Prompt for the existing password.
        #[arg(long)]
        current: bool,
        /// Remove the password instead of setting a new one.
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        yes: bool,
    },
    /// List an AFC directory.
    List { udid: Udid, path: AfcPath },
    /// Read AFC file metadata.
    Info { udid: Udid, path: AfcPath },
    /// Read AFC storage capacity and free space.
    Storage { udid: Udid },
    /// Copy a device file to the host.
    Pull {
        udid: Udid,
        source: AfcPath,
        destination: PathBuf,
    },
    /// Copy a host file to the device.
    Push {
        udid: Udid,
        source: PathBuf,
        destination: AfcPath,
        #[arg(long)]
        yes: bool,
    },
    /// Create an AFC directory.
    Mkdir { udid: Udid, path: AfcPath },
    /// Remove an AFC path.
    Remove {
        udid: Udid,
        path: AfcPath,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Rename or move an AFC path.
    Move {
        udid: Udid,
        source: AfcPath,
        destination: AfcPath,
        #[arg(long)]
        yes: bool,
    },
    /// Mount the device media directory over FUSE until Ctrl-C.
    Mount {
        udid: Udid,
        /// Existing empty host directory to mount on.
        mountpoint: PathBuf,
        /// Mount this app's Documents container instead of the media directory.
        #[arg(long)]
        documents: Option<String>,
        /// Mount read-only.
        #[arg(long)]
        read_only: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the effective configuration.
    Show,
    /// Print the configuration file path.
    Path,
}

#[derive(Debug, Subcommand)]
enum AppCommand {
    /// List installed applications.
    List {
        udid: Udid,
        #[arg(long, value_enum, default_value_t = AppFilterArg::User)]
        filter: AppFilterArg,
    },
    /// Upload and install an IPA through AFC and installation_proxy.
    Install {
        udid: Udid,
        ipa: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    /// Sign an IPA with an Apple ID and install it (AltServer equivalent).
    Sign {
        udid: Udid,
        ipa: PathBuf,
        /// AltServer/SideStore-compatible anisette server URL.
        #[arg(long)]
        anisette_url: Option<String>,
        /// Developer team identifier; defaults to the account's first team.
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Uninstall an application by bundle identifier.
    Uninstall {
        udid: Udid,
        bundle_id: String,
        #[arg(long)]
        yes: bool,
    },
    /// List files in an application's container.
    Files {
        udid: Udid,
        bundle_id: String,
        path: AfcPath,
        #[arg(long)]
        documents: bool,
    },
    /// Copy a file from an application's container.
    Pull {
        udid: Udid,
        bundle_id: String,
        source: AfcPath,
        destination: PathBuf,
        #[arg(long)]
        documents: bool,
    },
    /// Copy a file into an application's container.
    Push {
        udid: Udid,
        bundle_id: String,
        source: PathBuf,
        destination: AfcPath,
        #[arg(long)]
        documents: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Save an application's SpringBoard icon as PNG.
    Icon {
        udid: Udid,
        bundle_id: String,
        destination: PathBuf,
    },
    /// Read and write back the SpringBoard icon state.
    RefreshIcons {
        udid: Udid,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AppFilterArg {
    User,
    System,
    All,
}

impl From<AppFilterArg> for AppFilter {
    fn from(value: AppFilterArg) -> Self {
        match value {
            AppFilterArg::User => Self::User,
            AppFilterArg::System => Self::System,
            AppFilterArg::All => Self::All,
        }
    }
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// List normal, Recovery, DFU, WTF, and KIS devices.
    List,
    /// Diagnose USB permissions, driver bindings, and device contention.
    HostRequirements,
    /// Pair a normal-mode device through the configured backend.
    Pair { udid: Udid },
    /// Read battery diagnostics from a paired normal-mode device.
    Battery { udid: Udid },
    /// Query the device activation state.
    Activation { udid: Udid },
    /// Deactivate a paired normal-mode device.
    Deactivate {
        udid: Udid,
        #[arg(long)]
        yes: bool,
    },
    /// Erase all content and settings through mobilebackup2.
    Erase {
        udid: Udid,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Install TrollStore on iOS 15.2-16.6.1, 16.7 RC, or 17.0 (A9+) via the
    /// TrollRestore sparserestore exploit, replacing a removable system app.
    Trollrestore {
        udid: Udid,
        /// System app to replace with the TrollStore helper (default: Tips).
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Jailbreak an A5/A5X device on iOS 5.0-5.1.1 (iPhone4,1, iPad2,1-2,4,
    /// iPad3,1-3,3) with g1lbertJB. The device reboots once and you must tap
    /// the g1lbertJB home-screen icon when prompted. No data is lost, but
    /// back up your data just in case.
    JailbreakGilbert {
        udid: Udid,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Ask lockdownd to reboot a normal-mode device into Recovery mode.
    EnterRecovery {
        udid: Udid,
        #[arg(long)]
        yes: bool,
    },
    /// Query a device already in Recovery, DFU, WTF, or KIS mode.
    RecoveryInfo {
        #[arg(long)]
        ecid: Option<Ecid>,
    },
    /// Send an iBoot command to a Recovery-mode device.
    Iboot {
        command: String,
        #[arg(long)]
        ecid: Option<Ecid>,
    },
    /// Upload a boot image through Recovery or DFU.
    SendImage {
        path: PathBuf,
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        yes: bool,
    },
    /// Upload an exploit payload without completing the DFU transfer.
    SendPayload {
        path: PathBuf,
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        yes: bool,
    },
    /// Run limera1n against an S5L8920, S5L8922, or A4 device in DFU mode.
    PwnLimera1n {
        payload: PathBuf,
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        yes: bool,
    },
    /// Exploit an S5L8900 device in DFU mode with the Pwnage 2.0 WTF image.
    PwnWtf {
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        yes: bool,
    },
    /// Install the alloc8 exploit to the NOR of a new-bootrom iPhone 3GS in
    /// DFU mode. This permanently modifies the NOR and requires a prior
    /// custom 24Kpwn restore.
    InstallAlloc8 {
        #[arg(long)]
        ecid: Option<Ecid>,
        /// limera1n payload used to enter pwned DFU when the device is not
        /// already pwned.
        #[arg(long)]
        limera1n_payload: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Enter kDFU mode on a jailbroken device via kloader over SSH.
    EnterKdfu {
        udid: Udid,
        /// IPSW to extract and patch iBSS from (requires --key/--iv).
        #[arg(long, requires = "key")]
        firmware: Option<PathBuf>,
        #[arg(long, requires = "firmware", requires = "iv")]
        key: Option<String>,
        #[arg(long, requires = "key")]
        iv: Option<String>,
        /// Use a prebuilt RSA-patched iBSS instead of building one.
        #[arg(long, conflicts_with_all = ["firmware", "key", "iv"])]
        pwned_ibss: Option<PathBuf>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Hacktivate a jailbroken device over SSH (patched lockdownd or data_ark).
    Hacktivate {
        udid: Udid,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Revert hacktivation by restoring the original lockdownd.
    RevertHacktivate {
        udid: Udid,
        /// Use this lockdownd binary instead of the on-device backup.
        #[arg(long)]
        lockdownd: Option<PathBuf>,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// FourThree dualboot: query the highest completed step on the device.
    #[command(name = "fourthree-check")]
    FourThreeCheck {
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
    },
    /// FourThree step 2: partition a jailbroken iOS 6.1.3 iPad 2 over SSH.
    #[command(name = "fourthree-step2")]
    FourThreeStep2 {
        /// GB to leave for the iOS 6.1.3 data partition (the rest goes to 4.3.x).
        #[arg(long)]
        size_gb: u32,
        /// Directory to write the generated TwistedMind2 files to.
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// FourThree step 3: install the 4.3.x dualboot system over SSH.
    #[command(name = "fourthree-step3")]
    FourThreeStep3 {
        /// Device product type: iPad2,1, iPad2,2, or iPad2,3.
        #[arg(long)]
        device: ProductType,
        /// Base (dualbooted) iOS version, one of 4.3-4.3.5.
        #[arg(long)]
        base_version: String,
        /// Base iOS build, e.g. 8J2 for 4.3.3.
        #[arg(long)]
        base_build: String,
        /// Rebuilt 4.3.x RootFS.dmg.
        #[arg(long, required_unless_present = "components_dir")]
        rootfs: Option<PathBuf>,
        /// Patched decrypted 4.3.x kernelcache.
        #[arg(long, required_unless_present = "components_dir")]
        kernelcache: Option<PathBuf>,
        /// Patched 4.3.x LLB payload.
        #[arg(long, required_unless_present = "components_dir")]
        llb: Option<PathBuf>,
        /// Directory holding the RootFS.dmg, Kernelcache, and LLB produced by
        /// `firmware fourthree-prepare`.
        #[arg(long, conflicts_with_all = ["rootfs", "kernelcache", "llb"])]
        components_dir: Option<PathBuf>,
        /// Also install OpenSSH into the 4.3.x system.
        #[arg(long)]
        openssh: bool,
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Install the FourThree companion app on the 6.1.3 system.
    #[command(name = "fourthree-app")]
    FourThreeApp {
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Boot the 4.3.x system through the FourThree app (drops the SSH session).
    #[command(name = "fourthree-boot")]
    FourThreeBoot {
        #[arg(long, default_value = "root")]
        username: String,
        #[arg(long)]
        host_key: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Write the boot nonce generator to NVRAM on a Recovery-mode device.
    SetNonce {
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        generator: BootNonce,
        /// Also set auto-boot false and reset, keeping the device in Recovery.
        #[arg(long)]
        stay: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Set auto-boot and reboot a Recovery-mode device to normal mode.
    ExitRecovery {
        #[arg(long)]
        ecid: Option<Ecid>,
    },
    /// Reset the selected bootloader USB device.
    Reset {
        #[arg(long)]
        ecid: Option<Ecid>,
        #[arg(long)]
        yes: bool,
    },
    /// Restart a paired normal-mode device.
    Restart {
        udid: Udid,
        #[arg(long)]
        yes: bool,
    },
    /// Shut down a paired normal-mode device.
    Shutdown {
        udid: Udid,
        #[arg(long)]
        yes: bool,
    },
    /// Read a finite batch of lines from the device syslog relay.
    Syslog {
        udid: Udid,
        #[arg(long, default_value_t = 20)]
        lines: usize,
    },
}

#[derive(Debug, Subcommand)]
enum FirmwareCommand {
    /// Inspect a local IPSW and its BuildManifest.
    Inspect { path: PathBuf },
    /// Inspect a remote IPSW by fetching only its ZIP directory and BuildManifest.
    InspectRemote { url: String },
    /// Download and verify a resource from the provenance catalog.
    FetchResource {
        id: String,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Inspect or modify a raw HFS+/HFSX filesystem image.
    Hfs {
        #[command(subcommand)]
        command: HfsCommand,
    },
    /// Extract or replace IMG3/IM4P payload bytes.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Decrypt a FileVault v2 root filesystem DMG with its firmware key.
    DecryptDmg {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long, value_name = "HEX")]
        key: String,
        #[arg(long)]
        yes: bool,
    },
    /// Build a custom IPSW by replacing or removing archive entries.
    Build {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long = "replace", value_name = "ENTRY=FILE")]
        replacements: Vec<String>,
        #[arg(long = "remove", value_name = "ENTRY")]
        removals: Vec<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Modify the selected identity's root filesystem and rebuild the IPSW.
    BuildRootfs {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long, value_enum, default_value_t = RestoreBehaviorArg::Erase)]
        behavior: RestoreBehaviorArg,
        #[arg(long, value_name = "HEX")]
        key: Option<String>,
        #[arg(long)]
        grow: Option<usize>,
        #[arg(long = "add", value_name = "HFS_PATH=FILE")]
        additions: Vec<String>,
        #[arg(long = "remove", value_name = "HFS_PATH")]
        removals: Vec<String>,
        #[arg(long)]
        recursive: bool,
        #[arg(long = "mkdir", value_name = "HFS_PATH")]
        directories: Vec<String>,
        #[arg(long = "move", value_name = "SOURCE=DESTINATION")]
        moves: Vec<String>,
        #[arg(long = "chmod", value_name = "HFS_PATH=MODE")]
        modes: Vec<String>,
        #[arg(long = "chown", value_name = "HFS_PATH=UID:GID")]
        owners: Vec<String>,
        #[arg(long = "tar", value_name = "ARCHIVE")]
        archives: Vec<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
    /// Build the two custom IPSWs of an iOS 3.x/4.x multipart restore:
    /// the iOS 5.1.1-based NOR flash IPSW and the multipatched target IPSW.
    MultipartPrepare {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        /// Original IPSW of the target iOS version.
        #[arg(long)]
        target_ipsw: PathBuf,
        /// powdersn0w-built custom IPSW of the target version (part 2 base).
        #[arg(long)]
        custom_ipsw: PathBuf,
        /// IPSW of the device's latest (base) version; supplies the all_flash
        /// contents of the part 1 IPSW.
        #[arg(long)]
        base_ipsw: PathBuf,
        /// Local iOS 5.1.1 (9B206) IPSW supplying the NOR restore components.
        #[arg(long, conflicts_with = "nor_url", required_unless_present = "nor_url")]
        nor_ipsw: Option<PathBuf>,
        /// URL of the iOS 5.1.1 (9B206) IPSW, read through HTTP range requests.
        #[arg(long)]
        nor_url: Option<String>,
        /// Saved signing ticket (SHSH blob) holding the device APTicket.
        #[arg(long)]
        ticket: PathBuf,
        /// Output path of the part 1 (NOR flash) IPSW.
        #[arg(long)]
        part1: PathBuf,
        /// Output path of the part 2 (multipatched target) IPSW.
        #[arg(long)]
        part2: PathBuf,
        /// Artifact cache for firmware keys and catalog resources.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// bsdiff patch applied to the part 2 ramdisk ASR binary; without it
        /// the ramdisk keeps the ASR binary of the custom IPSW. The part 1
        /// ramdisk always uses the bundled iOS 5.1.1 ASR patch.
        #[arg(long)]
        asr_patch: Option<PathBuf>,
        /// powdersn0w exploit payload installed as /exploit in the part 2
        /// ramdisk of iOS 4.x targets.
        #[arg(long)]
        exploit: Option<PathBuf>,
        /// Add UpdateBaseband=false to the part 2 ramdisk options.plist.
        #[arg(long)]
        disable_bbupdate: bool,
        /// Patch the target iBoot of the part 1 IPSW with verbose boot-args.
        #[arg(long)]
        ipsw_verbose: bool,
        /// Extra boot-args appended to the target iBoot boot-args.
        #[arg(long)]
        bootargs: Option<String>,
        /// Output path of the patched target iBoot sidecar required on
        /// iPad1,1: the raw iBoot for iOS 3 targets, or a tar holding it as
        /// iBEC for iOS 4 targets.
        #[arg(long)]
        iboot_output: Option<PathBuf>,
        /// Keep the existing part 2 IPSW and build only the part 1 NOR flash
        /// IPSW, for powdersn0w 4.2.x and lower restores.
        #[arg(long)]
        skip_first: bool,
    },
    /// Build a powdersn0w custom IPSW: a single-IPSW build without --base-ipsw,
    /// a two-bundle (-base) build with one, or the 4.3.x ios4powder variant
    /// when the target is 4.3.x and --apticket is supplied.
    #[command(name = "powder-prepare")]
    PowderPrepare {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        /// Original IPSW of the target iOS version.
        #[arg(long)]
        target_ipsw: PathBuf,
        /// IPSW of the base iOS version of a two-bundle build.
        #[arg(long)]
        base_ipsw: Option<PathBuf>,
        /// Saved signing ticket (SHSH blob) whose APTicket is resealed into
        /// the scab template; required for the 4.3.x ios4powder variant.
        #[arg(long)]
        apticket: Option<PathBuf>,
        /// Resolve the jailbreak payload matrix.
        #[arg(long)]
        jailbreak: bool,
        /// Include the OpenSSH payload tar set (upstream default).
        #[arg(long, default_value_t = true, overrides_with = "no_openssh")]
        openssh: bool,
        /// Omit the OpenSSH payload tar set.
        #[arg(long)]
        no_openssh: bool,
        /// Accepted for parity with upstream's --memory; the builder always
        /// assembles payloads in memory.
        #[arg(long)]
        memory: bool,
        /// Verbose boot-args variant (pio-error=0 -v).
        #[arg(long)]
        ipsw_verbose: bool,
        /// Extra boot-args appended to the boot-args string.
        #[arg(long)]
        bootargs: Option<String>,
        /// Skip the latest-baseband swap (device_disable_bbupdate).
        #[arg(long)]
        disable_bbupdate: bool,
        /// Activation records tar merged into the root filesystem.
        #[arg(long)]
        activation_records: Option<PathBuf>,
        /// Externally patched iBoot binary merged as iBoot.tar (named iBEC on
        /// iPad1,1); required for ios4powder and ramdiskH two-bundle builds.
        #[arg(long)]
        iboot: Option<PathBuf>,
        /// Output path of the custom IPSW.
        #[arg(long, short = 'o')]
        output_ipsw: PathBuf,
        /// Artifact cache for firmware keys and catalog resources.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Build a classic (xpwn ipsw) custom IPSW for old devices: S5L8900
    /// (iPhone 2G/3G, iPod touch 1G) and S5L8720/8920/8922/A4 targets that
    /// upstream routes to the classic tool (iPhone2,1, iPod2,1, and pre-4.2
    /// blob restores).
    #[command(name = "classic-prepare")]
    ClassicPrepare {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        /// Original IPSW of the target iOS version.
        #[arg(long)]
        target_ipsw: PathBuf,
        /// Resolve the jailbreak payload matrix.
        #[arg(long)]
        jailbreak: bool,
        /// Include the OpenSSH payload tar set (upstream default).
        #[arg(long, default_value_t = true, overrides_with = "no_openssh")]
        openssh: bool,
        /// Omit the OpenSSH payload tar set.
        #[arg(long)]
        no_openssh: bool,
        /// Patch lockdownd in the root filesystem (hacktivation); requires
        /// --jailbreak and an iPhone/iPad1,1 on iOS 3.1-6.x.
        #[arg(long)]
        hacktivate: bool,
        /// Beta target: merge a generated systemversion.tar.
        #[arg(long)]
        beta: bool,
        /// Old-bootrom iPod2,1 on a 3.1/4.0 target (24kpwn).
        #[arg(long = "24kpwn-old-bootrom")]
        old_bootrom_24kpwn: bool,
        /// Skip the baseband update (device_disable_bbupdate).
        #[arg(long)]
        disable_bbupdate: bool,
        /// Activation records tar merged into the root filesystem.
        #[arg(long)]
        activation_records: Option<PathBuf>,
        /// Baseband tar merged into the root filesystem (device_deadbb).
        #[arg(long)]
        baseband: Option<PathBuf>,
        /// Externally patched iBoot binary merged as iBoot.tar (named iBEC on
        /// iPad1,1).
        #[arg(long)]
        iboot: Option<PathBuf>,
        /// The device's latest iOS version, driving the old-mode derivation;
        /// pass the target version to force the non-old iPhone2,1
        /// blob-restore path. Defaults to the target version.
        #[arg(long)]
        latest_version: Option<String>,
        /// Accepted for parity with upstream's --memory; the builder always
        /// assembles payloads in memory.
        #[arg(long)]
        memory: bool,
        /// Output path of the custom IPSW.
        #[arg(long, short = 'o')]
        output_ipsw: PathBuf,
        /// Artifact cache for firmware keys and catalog resources.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Build the FourThree custom 6.1.3 IPSW and the patched 4.3.x dualboot
    /// components (kernelcache, LLB, RootFS) of a FourThree install.
    #[command(name = "fourthree-prepare")]
    FourThreePrepare {
        /// Device product type: iPad2,1, iPad2,2, or iPad2,3.
        #[arg(long)]
        device: ProductType,
        /// Stock iOS 6.1.3 IPSW (the FourThree target system).
        #[arg(long)]
        target_ipsw: PathBuf,
        /// Stock IPSW of the base (dualbooted) iOS version, 4.3-4.3.5.
        #[arg(long)]
        base_ipsw: PathBuf,
        /// Local iOS 4.3.5 (8L1) IPSW supplying the bootchain components.
        #[arg(
            long,
            conflicts_with = "bootchain_url",
            required_unless_present = "bootchain_url"
        )]
        bootchain_ipsw: Option<PathBuf>,
        /// URL of the iOS 4.3.5 (8L1) IPSW, read through HTTP range requests.
        #[arg(long)]
        bootchain_url: Option<String>,
        /// Output path of the custom 6.1.3 IPSW.
        #[arg(long)]
        output_ipsw: PathBuf,
        /// Directory the patched Kernelcache, LLB, and RootFS.dmg are written to.
        #[arg(long)]
        components_dir: PathBuf,
        /// Artifact cache for firmware keys and catalog resources.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum HfsCommand {
    List {
        image: PathBuf,
        #[arg(default_value = "/")]
        path: String,
    },
    Stat {
        image: PathBuf,
        path: String,
    },
    Extract {
        image: PathBuf,
        path: String,
        destination: PathBuf,
    },
    Grow {
        source: PathBuf,
        destination: PathBuf,
        size: usize,
        #[arg(long)]
        yes: bool,
    },
    Add {
        source: PathBuf,
        destination: PathBuf,
        file: PathBuf,
        path: String,
        #[arg(long)]
        yes: bool,
    },
    Remove {
        source: PathBuf,
        destination: PathBuf,
        path: String,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        yes: bool,
    },
    Mkdir {
        source: PathBuf,
        destination: PathBuf,
        path: String,
        #[arg(long)]
        yes: bool,
    },
    Move {
        image: PathBuf,
        destination_image: PathBuf,
        source: String,
        destination: String,
        #[arg(long)]
        yes: bool,
    },
    Chmod {
        source: PathBuf,
        destination: PathBuf,
        path: String,
        mode: String,
        #[arg(long)]
        yes: bool,
    },
    Chown {
        source: PathBuf,
        destination: PathBuf,
        path: String,
        owner: u32,
        group: u32,
        #[arg(long)]
        yes: bool,
    },
    Untar {
        source: PathBuf,
        destination: PathBuf,
        archive: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ImageCommand {
    Extract {
        source: PathBuf,
        destination: PathBuf,
        #[arg(long, requires = "iv")]
        key: Option<String>,
        #[arg(long, requires = "key")]
        iv: Option<String>,
    },
    Replace {
        source: PathBuf,
        payload: PathBuf,
        destination: PathBuf,
        #[arg(long, requires = "iv")]
        key: Option<String>,
        #[arg(long, requires = "key")]
        iv: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Patch a decrypted 32-bit iBoot/iBSS/iBEC image.
    PatchIboot32 {
        source: PathBuf,
        destination: PathBuf,
        /// Apply custom boot-args.
        #[arg(long, short = 'b', conflicts_with = "env_boot_args")]
        boot_args: Option<String>,
        /// Use the boot-args environment variable.
        #[arg(long)]
        env_boot_args: bool,
        /// Redirect a recovery console command handler: `--cmd-handler ticket=0x80000000`.
        #[arg(long, value_name = "CMD=PTR")]
        cmd_handler: Option<String>,
        /// Apply the debug-enabled patch.
        #[arg(long)]
        debug: bool,
        /// Apply the ticket patch.
        #[arg(long)]
        ticket: bool,
        /// Apply the iOS 10 local boot patch.
        #[arg(long, conflicts_with = "remote_boot")]
        local_boot: bool,
        /// Apply the iOS 10 remote boot patch.
        #[arg(long)]
        remote_boot: bool,
        /// Apply the boot-partition patch.
        #[arg(long)]
        boot_partition: bool,
        /// Apply the boot-partition patch for De Rebus Antiquis (iOS 9 or later).
        #[arg(long)]
        boot_partition9: bool,
        /// Apply the boot-ramdisk patch.
        #[arg(long)]
        boot_ramdisk: bool,
        /// Apply the setenv patch.
        #[arg(long)]
        setenv: bool,
        /// Disable KASLR.
        #[arg(long)]
        disable_kaslr: bool,
        /// Apply a custom background color.
        #[arg(long, value_name = "RRGGBB")]
        bgcolor: Option<String>,
        /// Fix AppleLogo for iOS 5+ iBoot (De Rebus Antiquis).
        #[arg(long)]
        logo: bool,
        /// Fix AppleLogo for iOS 4 iBoot (De Rebus Antiquis).
        #[arg(long = "logo4")]
        logo4: bool,
        /// Enable jumping to an iOS 4.3.3-or-lower iBoot.
        #[arg(long = "433")]
        jump_iboot_433: bool,
        /// Apply the default dualboot patches (iOS 5 -> iOS 10).
        #[arg(long)]
        dualboot: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RestoreCommand {
    /// Resolve and display a destructive restore plan without touching a device.
    Plan {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long, value_enum, default_value_t = RestoreBehaviorArg::Erase)]
        behavior: RestoreBehaviorArg,
        #[arg(long, conflicts_with = "onboard_ticket")]
        ticket: Option<PathBuf>,
        #[arg(long)]
        onboard_ticket: bool,
        /// Restore without a signing ticket on a pwned device.
        #[arg(long, conflicts_with_all = ["ticket", "onboard_ticket"])]
        skip_blob: bool,
        #[arg(long, conflicts_with = "no_baseband")]
        baseband: Option<PathBuf>,
        #[arg(long)]
        no_baseband: bool,
        #[arg(long)]
        sep: Option<PathBuf>,
        /// Do not send Restore SEP firmware to the device.
        #[arg(long, conflicts_with = "sep")]
        no_sep: bool,
        #[arg(long, value_enum, default_value_t = ExploitArg::Auto)]
        exploit: ExploitArg,
        /// Write the ticket generator to the device boot nonce NVRAM variable.
        #[arg(long)]
        set_nonce: bool,
    },
    /// Execute a restore using a provided ticket or live TSS signing.
    Execute {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        ticket: Option<PathBuf>,
        /// Restore without a signing ticket on a pwned device.
        #[arg(long, conflicts_with = "ticket")]
        skip_blob: bool,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = RestoreBehaviorArg::Erase)]
        behavior: RestoreBehaviorArg,
        #[arg(long, value_enum, default_value_t = ExploitArg::AlreadyPwned)]
        exploit: ExploitArg,
        #[arg(long)]
        limera1n_payload: Option<PathBuf>,
        #[arg(long, conflicts_with = "no_baseband")]
        baseband: Option<PathBuf>,
        #[arg(long)]
        no_baseband: bool,
        #[arg(long)]
        sep: Option<PathBuf>,
        /// Do not send Restore SEP firmware to the device.
        #[arg(long, conflicts_with = "sep")]
        no_sep: bool,
        #[arg(long)]
        flash_version_1: bool,
        /// Write the ticket generator to the device boot nonce NVRAM variable.
        #[arg(long)]
        set_nonce: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Restore a powdersn0w custom IPSW (from `lik firmware powder-prepare`):
    /// resolve the signing ticket per device class and the pwned-chain entry
    /// method, then run the single-stage erase restore with verification.
    Powder {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        /// powdersn0w-built custom IPSW of the target version.
        #[arg(long)]
        firmware: PathBuf,
        /// Base-version signing ticket (SHSH blob); required on
        /// A5/A5X/A6/A6X, on A4 it replaces the --latest-ipsw TSS fetch.
        #[arg(long, conflicts_with_all = ["latest_ipsw", "cpid", "bdid"])]
        ticket: Option<PathBuf>,
        /// A4 only: IPSW of the device's latest iOS version; its (OTA-signed)
        /// ticket is fetched from TSS and used for the restore.
        #[arg(long, requires_all = ["cpid", "bdid"])]
        latest_ipsw: Option<PathBuf>,
        #[arg(long, value_parser = parse_integer)]
        cpid: Option<u64>,
        #[arg(long, value_parser = parse_integer)]
        bdid: Option<u64>,
        /// Pwned-chain entry method; defaults to kDFU on A5/A5X/A6/A6X and
        /// pwnDFU on A4, mirroring upstream's recommended menu order.
        #[arg(long, value_enum)]
        pwn: Option<PowderPwnArg>,
        /// Directory the fetched latest-version ticket is saved to
        /// (defaults to the artifact cache's shsh directory).
        #[arg(long)]
        ticket_dir: Option<PathBuf>,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long)]
        limera1n_payload: Option<PathBuf>,
        /// Do not send baseband firmware during the restore.
        #[arg(long)]
        no_baseband: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Execute a two-stage iOS 3.x/4.x multipart restore: the part 1 NOR
    /// flash IPSW first, then the multipatched part 2 target IPSW after the
    /// device re-enters DFU/recovery.
    Multipart {
        #[arg(long)]
        device: ProductType,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        /// Part 1: iOS 5.1.1-based NOR flash IPSW.
        #[arg(long)]
        part1: PathBuf,
        /// Part 2: multipatched target IPSW.
        #[arg(long)]
        part2: PathBuf,
        /// Saved signing ticket (SHSH blob) for the part 1 restore.
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ExploitArg::AlreadyPwned)]
        exploit: ExploitArg,
        #[arg(long)]
        limera1n_payload: Option<PathBuf>,
        /// Do not send baseband firmware during the part 2 restore.
        #[arg(long)]
        no_baseband: bool,
        /// Skip the first restore and flash the part 2 IPSW only, for
        /// powdersn0w 4.2.x and lower restores.
        #[arg(long)]
        skip_first: bool,
        /// Also supply the --ticket blob to the part 2 restore, matching
        /// upstream's `-w` behavior. By default part 2 restores ticket-free:
        /// the multipatched boot chain is RSA-patched and never validates the
        /// blob, so this flag only matters for exact upstream parity.
        #[arg(long)]
        part2_ticket: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ShshCommand {
    /// Request and save a signing ticket from Apple's TSS service.
    Save {
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        board: BoardConfig,
        #[arg(long)]
        ecid: Ecid,
        #[arg(long, value_parser = parse_integer)]
        cpid: u64,
        #[arg(long, value_parser = parse_integer)]
        bdid: u64,
        #[arg(long, value_enum, default_value_t = RestoreBehaviorArg::Erase)]
        behavior: RestoreBehaviorArg,
        #[arg(long, value_enum, default_value_t = ImageFormatArg::Img4)]
        image_format: ImageFormatArg,
        #[arg(long, value_parser = parse_hex)]
        ap_nonce: Option<Vec<u8>>,
        #[arg(long, value_parser = parse_hex)]
        sep_nonce: Option<Vec<u8>>,
        #[arg(long)]
        destination: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ImageFormatArg {
    Img3,
    Img4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RestoreBehaviorArg {
    Erase,
    Update,
}

impl From<RestoreBehaviorArg> for RestoreBehavior {
    fn from(value: RestoreBehaviorArg) -> Self {
        match value {
            RestoreBehaviorArg::Erase => Self::Erase,
            RestoreBehaviorArg::Update => Self::Update,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ExploitArg {
    Auto,
    None,
    AlreadyPwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PowderPwnArg {
    Kdfu,
    Pwndfu,
}

impl From<PowderPwnArg> for PowderPwnMethod {
    fn from(value: PowderPwnArg) -> Self {
        match value {
            PowderPwnArg::Kdfu => Self::Kdfu,
            PowderPwnArg::Pwndfu => Self::PwnDfu,
        }
    }
}

impl From<ExploitArg> for ExploitPolicy {
    fn from(value: ExploitArg) -> Self {
        match value {
            ExploitArg::Auto => Self::Auto,
            ExploitArg::None => Self::None,
            ExploitArg::AlreadyPwned => Self::AlreadyPwned,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;
    let output = cli.output.or(config.output).unwrap_or_default();
    init_tracing(&cli, &config)?;
    let kit = LegacyIosKit::new()
        .with_normal_backend(config.transport.normal_backend)
        .with_pairing_store(config.pairing_dir()?);
    let kit = match config.network.tss_endpoint.as_deref() {
        Some(endpoint) => kit
            .with_tss_endpoint(endpoint)
            .context("invalid configured TSS endpoint")?,
        None => kit,
    };

    match cli.command {
        Command::App {
            command: AppCommand::List { udid, filter },
        } => {
            let apps = kit
                .devices()
                .list_apps(&udid, filter.into())
                .await
                .context("failed to list apps")?;
            write_apps(output, &apps)?;
        }
        Command::App {
            command: AppCommand::Install { udid, ipa, yes },
        } => {
            confirm("install the IPA", yes)?;
            kit.devices()
                .install_ipa(&udid, &ipa)
                .await
                .context("failed to install IPA")?;
            write_message(output, "installed-ipa", &udid)?;
        }
        Command::App {
            command:
                AppCommand::Sign {
                    udid,
                    ipa,
                    anisette_url,
                    team,
                    yes,
                },
        } => {
            confirm("sign and install the IPA with an Apple ID", yes)?;
            let anisette_url = anisette_url
                .or_else(|| config.network.anisette_url.clone())
                .context(
                    "an anisette server is required: pass --anisette-url or set \
                     network.anisette_url in the configuration",
                )?;
            let apple_id = prompt_text("Apple ID: ")?;
            let password = zeroize::Zeroizing::new(
                rpassword::prompt_password("Apple ID password: ")
                    .context("failed to read Apple ID password")?,
            );
            let request = AppSignRequest {
                anisette_url,
                apple_id,
                password,
                team_id: team,
            };
            let mut two_factor = || {
                prompt_text("Two-factor verification code: ")
                    .map_err(|_| legacy_ios_kit::signing::GsaError::TwoFactorCancelled)
            };
            let outcome = kit
                .devices()
                .sign_and_install_app(&udid, &ipa, &request, &mut two_factor)
                .await
                .context("failed to sign and install the IPA")?;
            write_sign_outcome(output, &outcome)?;
        }
        Command::App {
            command:
                AppCommand::Uninstall {
                    udid,
                    bundle_id,
                    yes,
                },
        } => {
            confirm(&format!("uninstall {bundle_id}"), yes)?;
            kit.devices()
                .uninstall_app(&udid, &bundle_id)
                .await
                .context("failed to uninstall application")?;
            write_message(output, "uninstalled-app", &udid)?;
        }
        Command::App {
            command:
                AppCommand::Files {
                    udid,
                    bundle_id,
                    path,
                    documents,
                },
        } => {
            let mut files = if documents {
                kit.devices().app_documents(&udid, &bundle_id).await?
            } else {
                kit.devices().app_container(&udid, &bundle_id).await?
            };
            write_data_list(output, &files.list(&path).await?)?;
        }
        Command::App {
            command:
                AppCommand::Pull {
                    udid,
                    bundle_id,
                    source,
                    destination,
                    documents,
                },
        } => {
            let mut files = if documents {
                kit.devices().app_documents(&udid, &bundle_id).await?
            } else {
                kit.devices().app_container(&udid, &bundle_id).await?
            };
            let data = files.read(&source).await?;
            tokio::fs::write(&destination, data)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "pulled-app-file")?;
        }
        Command::App {
            command:
                AppCommand::Push {
                    udid,
                    bundle_id,
                    source,
                    destination,
                    documents,
                    yes,
                },
        } => {
            confirm("write the application container file", yes)?;
            let data = tokio::fs::read(&source)
                .await
                .with_context(|| format!("failed to read {}", source.display()))?;
            let mut files = if documents {
                kit.devices().app_documents(&udid, &bundle_id).await?
            } else {
                kit.devices().app_container(&udid, &bundle_id).await?
            };
            files.write(&destination, &data).await?;
            write_status(output, "pushed-app-file")?;
        }
        Command::App {
            command:
                AppCommand::Icon {
                    udid,
                    bundle_id,
                    destination,
                },
        } => {
            let icon = kit.devices().app_icon(&udid, &bundle_id).await?;
            tokio::fs::write(&destination, icon)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "saved-app-icon")?;
        }
        Command::App {
            command: AppCommand::RefreshIcons { udid, yes },
        } => {
            confirm("write the SpringBoard icon state", yes)?;
            kit.devices().refresh_icon_state(&udid).await?;
            write_message(output, "refreshed-icons", &udid)?;
        }
        Command::Config {
            command: ConfigCommand::Show,
        } => write_config(output, &config)?,
        Command::Config {
            command: ConfigCommand::Path,
        } => write_path(output, &config.path)?,
        Command::Data {
            command:
                DataCommand::Backup {
                    udid,
                    destination,
                    full,
                },
        } => {
            let outcome = kit
                .devices()
                .backup(
                    &udid,
                    &destination,
                    BackupOptions::default().force_full(full),
                )
                .await
                .context("device backup failed")?;
            write_backup_outcome(output, &outcome)?;
        }
        Command::Data {
            command:
                DataCommand::Restore {
                    udid,
                    root,
                    source_identifier,
                    no_reboot,
                    replace_settings,
                    system_files,
                    remove_missing,
                    password,
                    yes,
                },
        } => {
            confirm("restore the device backup", yes)?;
            let mut options = BackupRestoreOptions::default()
                .reboot(!no_reboot)
                .preserve_settings(!replace_settings)
                .system_files(system_files)
                .remove_items_not_restored(remove_missing);
            if password {
                options = options.with_password(BackupPassword::new(
                    rpassword::prompt_password("Backup password: ")
                        .context("failed to read backup password")?,
                ));
            }
            let outcome = kit
                .devices()
                .restore_backup(&udid, &root, &source_identifier, options)
                .await
                .context("device backup restore failed")?;
            write_backup_outcome(output, &outcome)?;
        }
        Command::Data {
            command:
                DataCommand::Encryption {
                    udid,
                    work_dir,
                    current,
                    remove,
                    yes,
                },
        } => {
            confirm("change device backup encryption", yes)?;
            let old = current
                .then(|| {
                    rpassword::prompt_password("Current backup password: ")
                        .context("failed to read current backup password")
                        .map(BackupPassword::new)
                })
                .transpose()?;
            let new = (!remove)
                .then(|| {
                    rpassword::prompt_password("New backup password: ")
                        .context("failed to read new backup password")
                        .map(BackupPassword::new)
                })
                .transpose()?;
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit-backup"));
            let outcome = kit
                .devices()
                .change_backup_password(&udid, &work_directory, old.as_ref(), new.as_ref())
                .await
                .context("failed to change backup encryption")?;
            write_backup_outcome(output, &outcome)?;
        }
        Command::Data {
            command: DataCommand::List { udid, path },
        } => {
            let mut files = kit.devices().files(&udid).await?;
            let entries = files.list(&path).await?;
            write_data_list(output, &entries)?;
        }
        Command::Data {
            command: DataCommand::Info { udid, path },
        } => {
            let mut files = kit.devices().files(&udid).await?;
            write_file_info(output, &files.info(&path).await?)?;
        }
        Command::Data {
            command: DataCommand::Storage { udid },
        } => {
            let mut files = kit.devices().files(&udid).await?;
            write_storage_info(output, &files.storage_info().await?)?;
        }
        Command::Data {
            command:
                DataCommand::Pull {
                    udid,
                    source,
                    destination,
                },
        } => {
            let mut files = kit.devices().files(&udid).await?;
            let data = files.read(&source).await?;
            tokio::fs::write(&destination, data)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "pulled-file")?;
        }
        Command::Data {
            command:
                DataCommand::Push {
                    udid,
                    source,
                    destination,
                    yes,
                },
        } => {
            confirm("write the device file", yes)?;
            let data = tokio::fs::read(&source)
                .await
                .with_context(|| format!("failed to read {}", source.display()))?;
            kit.devices()
                .files(&udid)
                .await?
                .write(&destination, &data)
                .await?;
            write_status(output, "pushed-file")?;
        }
        Command::Data {
            command: DataCommand::Mkdir { udid, path },
        } => {
            kit.devices().files(&udid).await?.create_dir(&path).await?;
            write_status(output, "created-directory")?;
        }
        Command::Data {
            command:
                DataCommand::Remove {
                    udid,
                    path,
                    recursive,
                    yes,
                },
        } => {
            confirm("remove the device path", yes)?;
            kit.devices()
                .files(&udid)
                .await?
                .remove(&path, recursive)
                .await?;
            write_status(output, "removed-path")?;
        }
        Command::Data {
            command:
                DataCommand::Move {
                    udid,
                    source,
                    destination,
                    yes,
                },
        } => {
            confirm("move the device path", yes)?;
            kit.devices()
                .files(&udid)
                .await?
                .rename(&source, &destination)
                .await?;
            write_status(output, "moved-path")?;
        }
        Command::Data {
            command:
                DataCommand::Mount {
                    udid,
                    mountpoint,
                    documents,
                    read_only,
                },
        } => {
            let files = match &documents {
                Some(bundle_id) => kit.devices().app_documents(&udid, bundle_id).await?,
                None => kit.devices().files(&udid).await?,
            };
            let guard = files
                .mount(&mountpoint, MountOptions::default().read_only(read_only))
                .context("failed to mount device files")?;
            write_status(output, "mounted")?;
            info!(mountpoint = %mountpoint.display(), "mounted; press Ctrl-C to unmount");
            tokio::signal::ctrl_c().await?;
            guard.unmount().context("failed to unmount device files")?;
            write_status(output, "unmounted")?;
        }
        Command::Device {
            command: DeviceCommand::List,
        } => {
            let inventory = kit
                .devices()
                .list()
                .await
                .context("failed to list devices")?;
            write_inventory(output, &inventory)?;
        }
        Command::Device {
            command: DeviceCommand::HostRequirements,
        } => {
            let diagnostics = kit
                .devices()
                .host_requirements()
                .await
                .context("failed to diagnose USB host requirements")?;
            write_host_requirements(output, &diagnostics)?;
        }
        Command::Device {
            command: DeviceCommand::Pair { udid },
        } => {
            kit.devices()
                .pair(&udid)
                .await
                .context("failed to pair device")?;
            write_message(output, "paired", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::Battery { udid },
        } => {
            let diagnostics = kit
                .devices()
                .battery_info(&udid)
                .await
                .context("failed to read battery diagnostics")?;
            write_diagnostics(output, &diagnostics)?;
        }
        Command::Device {
            command: DeviceCommand::Activation { udid },
        } => {
            let state = kit.devices().activation_state(&udid).await?;
            write_activation_state(output, &state)?;
        }
        Command::Device {
            command: DeviceCommand::Deactivate { udid, yes },
        } => {
            confirm("deactivate the device", yes)?;
            kit.devices().deactivate(&udid).await?;
            write_message(output, "deactivated", &udid)?;
        }
        Command::Device {
            command:
                DeviceCommand::Erase {
                    udid,
                    work_dir,
                    yes,
                },
        } => {
            let plan = kit.plan_erase(udid).await?;
            confirm(
                &format!("erase all content on the device with plan {}", plan.id()),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit-erase"));
            consume_operation(output, kit.execute_erase(plan, consent, work_directory)).await?;
        }
        Command::Device {
            command:
                DeviceCommand::Trollrestore {
                    udid,
                    app,
                    work_dir,
                    yes,
                },
        } => {
            let app = match app {
                Some(app) => app,
                None => prompt_with_default(
                    "Enter the removable system app to replace with the TrollStore helper",
                    legacy_ios_kit::TROLLRESTORE_DEFAULT_APP,
                )?,
            };
            let plan = kit.plan_trollrestore(udid, &app).await?;
            confirm(
                &format!(
                    "replace {} with the TrollStore helper and reboot, with plan {}",
                    plan.app(),
                    plan.id()
                ),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            let cache = config.artifact_cache_dir()?;
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit-trollrestore"));
            consume_operation(
                output,
                kit.execute_trollrestore(plan, consent, cache, work_directory),
            )
            .await?;
        }
        Command::Device {
            command:
                DeviceCommand::JailbreakGilbert {
                    udid,
                    work_dir,
                    yes,
                },
        } => {
            let plan = kit.plan_gilbertjb(udid).await?;
            confirm(
                &format!(
                    "jailbreak the {} on iOS {} ({}) with g1lbertJB and reboot it, with plan {}",
                    plan.product_type(),
                    plan.version(),
                    plan.build(),
                    plan.id()
                ),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            let cache = config.artifact_cache_dir()?;
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit-gilbertjb"));
            consume_operation(
                output,
                kit.execute_gilbertjb(plan, consent, cache, work_directory),
            )
            .await?;
        }
        Command::Device {
            command: DeviceCommand::EnterRecovery { udid, yes },
        } => {
            confirm("enter Recovery mode", yes)?;
            kit.devices()
                .enter_recovery(&udid)
                .await
                .context("failed to enter Recovery mode")?;
            write_message(output, "entered-recovery", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::RecoveryInfo { ecid },
        } => {
            let device = kit.recovery().open(ecid).await?;
            write_recovery_info(output, device.mode(), device.info())?;
        }
        Command::Device {
            command: DeviceCommand::Iboot { command, ecid },
        } => {
            kit.recovery()
                .open(ecid)
                .await?
                .send_command(&command)
                .await?;
            write_status(output, "sent-command")?;
        }
        Command::Device {
            command: DeviceCommand::SendImage { path, ecid, yes },
        } => {
            confirm("upload the boot image", yes)?;
            let data = tokio::fs::read(path).await?;
            let result = kit.recovery().open(ecid).await?.upload_image(&data).await?;
            let status = match result {
                RecoveryUploadResult::Connected(_) => "uploaded-image",
                RecoveryUploadResult::Reenumerating => "uploaded-image-reenumerating",
            };
            write_status(output, status)?;
        }
        Command::Device {
            command: DeviceCommand::SendPayload { path, ecid, yes },
        } => {
            confirm("upload the exploit payload", yes)?;
            let data = tokio::fs::read(path).await?;
            kit.recovery()
                .open(ecid)
                .await?
                .upload_payload(&data)
                .await?;
            write_status(output, "uploaded-payload")?;
        }
        Command::Device {
            command: DeviceCommand::PwnLimera1n { payload, ecid, yes },
        } => {
            confirm("run limera1n", yes)?;
            let payload = tokio::fs::read(payload)
                .await
                .context("failed to read limera1n payload")?;
            let device = kit.recovery().open(ecid).await?.limera1n(payload).await?;
            write_recovery_info(output, device.mode(), device.info())?;
        }
        Command::Device {
            command: DeviceCommand::PwnWtf { ecid, yes },
        } => {
            confirm("run the Pwnage 2.0 WTF exploit", yes)?;
            kit.pwn_wtf(ecid, config.artifact_cache_dir()?)
                .await
                .context("Pwnage WTF exploit failed")?;
            write_status(output, "pwned-wtf")?;
        }
        Command::Device {
            command:
                DeviceCommand::InstallAlloc8 {
                    ecid,
                    limera1n_payload,
                    yes,
                },
        } => {
            confirm(
                "permanently install the alloc8 exploit to the device NOR",
                yes,
            )?;
            let limera1n_payload = match limera1n_payload {
                Some(path) => Some(
                    tokio::fs::read(path)
                        .await
                        .context("failed to read limera1n payload")?,
                ),
                None => None,
            };
            kit.install_alloc8(ecid, limera1n_payload, config.artifact_cache_dir()?)
                .await
                .context(
                    "alloc8 install failed; force restart the device, re-enter DFU mode, and retry",
                )?;
            write_status(output, "installed-alloc8")?;
        }
        Command::Device {
            command:
                DeviceCommand::EnterKdfu {
                    udid,
                    firmware,
                    key,
                    iv,
                    pwned_ibss,
                    username,
                    host_key,
                    yes,
                },
        } => {
            let summaries = kit.devices().list_normal().await?;
            let device = summaries
                .iter()
                .find(|device| device.udid() == Some(&udid))
                .ok_or_else(|| anyhow!("no normal-mode device with UDID {udid}"))?;
            let product_type = device
                .product_type()
                .ok_or_else(|| anyhow!("device product type is unknown"))?
                .clone();
            let ios_major: u32 = device
                .product_version()
                .and_then(|version| version.split('.').next()?.parse().ok())
                .ok_or_else(|| anyhow!("device iOS version is unknown"))?;
            let ecid = device.ecid();

            let pwned_ibss = if let Some(path) = pwned_ibss {
                tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("failed to read {}", path.display()))?
            } else {
                let firmware = firmware.ok_or_else(|| {
                    anyhow!("either --firmware with --key/--iv or --pwned-ibss is required")
                })?;
                let board = device
                    .board_config()
                    .ok_or_else(|| anyhow!("device board config is unknown"))?
                    .clone();
                let cipher = image_cipher(key, iv)?;
                tokio::task::spawn_blocking(move || {
                    legacy_ios_kit::prepare_pwned_ibss(&firmware, &board, cipher.as_ref())
                })
                .await
                .map_err(|error| anyhow!("task failed: {error}"))??
            };

            let kloader_id = legacy_ios_kit::select_kloader(&product_type, ios_major);
            let kloader_path = kit
                .fetch_resource(&kloader_id, config.artifact_cache_dir()?)
                .await?;
            let kloader = tokio::fs::read(&kloader_path).await?;

            confirm("enter kDFU mode on the device", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.enter_kdfu(&ssh, &kloader, &pwned_ibss, ecid)
                .await
                .context("failed to enter kDFU mode")?;
            write_status(output, "entered-kdfu")?;
        }
        Command::Device {
            command:
                DeviceCommand::Hacktivate {
                    udid,
                    username,
                    host_key,
                    yes,
                },
        } => {
            let summaries = kit.devices().list_normal().await?;
            let device = summaries
                .iter()
                .find(|device| device.udid() == Some(&udid))
                .ok_or_else(|| anyhow!("no normal-mode device with UDID {udid}"))?;
            let product_type = device
                .product_type()
                .ok_or_else(|| anyhow!("device product type is unknown"))?
                .as_str()
                .to_owned();
            let version = device
                .product_version()
                .ok_or_else(|| anyhow!("device iOS version is unknown"))?
                .to_owned();
            let build = device
                .build_version()
                .ok_or_else(|| anyhow!("device build version is unknown"))?
                .to_owned();
            let method = legacy_ios_kit::hacktivate_method(&product_type, &version, &build)
                .ok_or_else(|| {
                    anyhow!("no hacktivation method for {product_type} {version} ({build})")
                })?;
            let patch = if let legacy_ios_kit::HacktivateMethod::LockdowndPatch(id) = &method {
                let path = kit.fetch_resource(id, config.artifact_cache_dir()?).await?;
                Some(tokio::fs::read(&path).await?)
            } else {
                None
            };
            confirm("hacktivate the device", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.hacktivate(&ssh, &method, patch.as_deref())
                .await
                .context("hacktivation failed")?;
            write_status(output, "hacktivated")?;
        }
        Command::Device {
            command:
                DeviceCommand::RevertHacktivate {
                    udid: _,
                    lockdownd,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("revert hacktivation on the device", yes)?;
            let original = match lockdownd {
                Some(path) => Some(tokio::fs::read(&path).await?),
                None => None,
            };
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.revert_hacktivate(&ssh, original.as_deref())
                .await
                .context("reverting hacktivation failed")?;
            write_status(output, "reverted-hacktivation")?;
        }
        Command::Device {
            command: DeviceCommand::FourThreeCheck { username, host_key },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            let step = kit
                .fourthree_check(&ssh)
                .await
                .context("FourThree check failed")?;
            write_status(output, &format!("fourthree-{}", step.as_str()))?;
        }
        Command::Device {
            command:
                DeviceCommand::FourThreeStep2 {
                    size_gb,
                    output_dir,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("partition the device for the FourThree dualboot", yes)?;
            let path = kit
                .fetch_resource(
                    &ResourceId::new("jailbreak-dualbootstuff"),
                    config.artifact_cache_dir()?,
                )
                .await?;
            let dualbootstuff = tokio::fs::read(&path).await?;
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            let outputs = kit
                .fourthree_step2(&ssh, &dualbootstuff, size_gb)
                .await
                .context("FourThree step 2 (partition) failed")?;
            tokio::fs::create_dir_all(&output_dir).await?;
            for file in &outputs {
                tokio::fs::write(output_dir.join(file.name()), file.data()).await?;
            }
            write_status(output, "fourthree-partitioned")?;
        }
        Command::Device {
            command:
                DeviceCommand::FourThreeStep3 {
                    device,
                    base_version,
                    base_build,
                    rootfs,
                    kernelcache,
                    llb,
                    components_dir,
                    openssh,
                    username,
                    host_key,
                    yes,
                },
        } => {
            let product_type = device.as_str();
            if legacy_ios_kit::fourthree_board_config(product_type).is_none() {
                return Err(anyhow!(
                    "FourThree supports iPad2,1/iPad2,2/iPad2,3, found {product_type}"
                ));
            }
            let (rootfs, kernelcache, llb) = match (components_dir, rootfs, kernelcache, llb) {
                (Some(dir), None, None, None) => (
                    dir.join("RootFS.dmg"),
                    dir.join("Kernelcache"),
                    dir.join("LLB"),
                ),
                (None, Some(rootfs), Some(kernelcache), Some(llb)) => (rootfs, kernelcache, llb),
                _ => {
                    return Err(anyhow!(
                        "provide either --components-dir or all of --rootfs, --kernelcache, and --llb"
                    ));
                }
            };
            confirm(
                "install the FourThree 4.3.x dualboot system on the device",
                yes,
            )?;
            let cache = config.artifact_cache_dir()?;
            let fetch = async |id: &ResourceId, gz: bool| -> Result<Vec<u8>> {
                let path = kit.fetch_resource(id, &cache).await?;
                let data = tokio::fs::read(&path).await?;
                Ok(if gz {
                    legacy_ios_kit::gunzip(&data)?
                } else {
                    data
                })
            };
            let lockdownd_patch = if product_type == "iPad2,1" {
                None
            } else {
                let id = legacy_ios_kit::fourthree_lockdownd_patch_id(&base_version, &base_build);
                Some(fetch(&id, false).await?)
            };
            let openssh_packages = if openssh {
                Some(legacy_ios_kit::FourThreeOpenSsh {
                    sshdeb: fetch(&ResourceId::new("jailbreak-sshdeb"), false).await?,
                    openssh: fetch(&ResourceId::new("jailbreak-openssh"), true).await?,
                    openssl: fetch(&ResourceId::new("jailbreak-openssl"), true).await?,
                })
            } else {
                None
            };
            let packages = legacy_ios_kit::FourThreeStep3Packages {
                rootfs_dmg: tokio::fs::read(&rootfs).await?,
                kernelcache: tokio::fs::read(&kernelcache).await?,
                llb: tokio::fs::read(&llb).await?,
                freeze: fetch(&ResourceId::new("jailbreak-bootstrap-freeze"), true).await?,
                app: fetch(&ResourceId::new("jailbreak-fourthree-app"), false).await?,
                lockdownd_patch,
                openssh: openssh_packages,
            };
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.fourthree_step3(&ssh, product_type, &packages)
                .await
                .context("FourThree step 3 failed")?;
            write_status(output, "fourthree-installed")?;
        }
        Command::Device {
            command:
                DeviceCommand::FourThreeApp {
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("install the FourThree app on the device", yes)?;
            let path = kit
                .fetch_resource(
                    &ResourceId::new("jailbreak-fourthree-app"),
                    config.artifact_cache_dir()?,
                )
                .await?;
            let app = tokio::fs::read(&path).await?;
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.fourthree_install_app(&ssh, &app)
                .await
                .context("FourThree app installation failed")?;
            write_status(output, "fourthree-app-installed")?;
        }
        Command::Device {
            command:
                DeviceCommand::FourThreeBoot {
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("boot the 4.3.x dualboot system", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, None, &username, host_key).await?;
            kit.fourthree_boot(&ssh)
                .await
                .context("FourThree boot failed")?;
            write_status(output, "fourthree-booted")?;
        }
        Command::Device {
            command:
                DeviceCommand::SetNonce {
                    ecid,
                    generator,
                    stay,
                    yes,
                },
        } => {
            confirm(
                &format!("set the device boot nonce generator to {generator}"),
                yes,
            )?;
            let device = kit.recovery().open(ecid).await?;
            device.set_boot_nonce(generator).await?;
            if stay {
                device.send_command("setenv auto-boot false").await?;
                device.send_command("saveenv").await?;
                device.reset().await?;
                write_status(output, "set-nonce-reset-recovery")?;
            } else {
                write_status(output, "set-nonce")?;
            }
        }
        Command::Device {
            command: DeviceCommand::ExitRecovery { ecid },
        } => {
            kit.recovery().open(ecid).await?.reboot_to_normal().await?;
            write_status(output, "exited-recovery")?;
        }
        Command::Device {
            command: DeviceCommand::Reset { ecid, yes },
        } => {
            confirm("reset the USB device", yes)?;
            kit.recovery().open(ecid).await?.reset().await?;
            write_status(output, "reset-device")?;
        }
        Command::Device {
            command: DeviceCommand::Restart { udid, yes },
        } => {
            confirm("restart the device", yes)?;
            kit.devices()
                .restart(&udid)
                .await
                .context("failed to restart device")?;
            write_message(output, "restarted", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::Shutdown { udid, yes },
        } => {
            confirm("shut down the device", yes)?;
            kit.devices()
                .shutdown(&udid)
                .await
                .context("failed to shut down device")?;
            write_message(output, "shut-down", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::Syslog { udid, lines },
        } => {
            let mut syslog = kit
                .devices()
                .syslog(&udid)
                .await
                .context("failed to connect to device syslog")?;
            let mut records = Vec::with_capacity(lines);
            for _ in 0..lines {
                records.push(
                    syslog
                        .next_line()
                        .await
                        .context("failed to read device syslog")?
                        .trim_end_matches(['\n', '\0'])
                        .to_owned(),
                );
            }
            write_syslog(output, &records)?;
        }
        Command::Firmware {
            command: FirmwareCommand::Inspect { path },
        } => {
            let summary = kit
                .inspect_firmware(path)
                .context("failed to inspect firmware")?;
            write_firmware(output, &summary)?;
        }
        Command::Firmware {
            command: FirmwareCommand::InspectRemote { url },
        } => {
            let summary = kit
                .inspect_remote_firmware(url)
                .await
                .context("failed to inspect remote firmware")?;
            write_remote_firmware(output, &summary)?;
        }
        Command::Firmware {
            command: FirmwareCommand::FetchResource { id, cache_dir },
        } => {
            let path = kit
                .fetch_resource(
                    &ResourceId::new(id),
                    match cache_dir {
                        Some(path) => path,
                        None => config.artifact_cache_dir()?,
                    },
                )
                .await
                .context("failed to fetch resource")?;
            write_path(output, &path)?;
        }
        Command::Firmware {
            command: FirmwareCommand::Hfs { command },
        } => match command {
            HfsCommand::List { image, path } => {
                write_hfs_entries(output, &kit.list_hfs(image, path).await?)?;
            }
            HfsCommand::Stat { image, path } => {
                write_hfs_stat(output, &kit.stat_hfs(image, path).await?)?;
            }
            HfsCommand::Extract {
                image,
                path,
                destination,
            } => {
                kit.extract_hfs_file(image, path, destination).await?;
                write_status(output, "extracted-hfs-file")?;
            }
            HfsCommand::Grow {
                source,
                destination,
                size,
                yes,
            } => {
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::Grow { size },
                    yes,
                )
                .await?;
            }
            HfsCommand::Add {
                source,
                destination,
                file,
                path,
                yes,
            } => {
                let data = tokio::fs::read(&file)
                    .await
                    .with_context(|| format!("failed to read {}", file.display()))?;
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::AddFile { path, data },
                    yes,
                )
                .await?;
            }
            HfsCommand::Remove {
                source,
                destination,
                path,
                recursive,
                yes,
            } => {
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::Remove { path, recursive },
                    yes,
                )
                .await?;
            }
            HfsCommand::Mkdir {
                source,
                destination,
                path,
                yes,
            } => {
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::CreateDirectory { path },
                    yes,
                )
                .await?;
            }
            HfsCommand::Move {
                image,
                destination_image,
                source,
                destination,
                yes,
            } => {
                edit_hfs(
                    &kit,
                    output,
                    image,
                    destination_image,
                    HfsMutation::Move {
                        source,
                        destination,
                    },
                    yes,
                )
                .await?;
            }
            HfsCommand::Chmod {
                source,
                destination,
                path,
                mode,
                yes,
            } => {
                let mode = u16::from_str_radix(mode.trim_start_matches("0o"), 8)
                    .context("HFS mode must be octal")?;
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::Chmod { path, mode },
                    yes,
                )
                .await?;
            }
            HfsCommand::Chown {
                source,
                destination,
                path,
                owner,
                group,
                yes,
            } => {
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::Chown { path, owner, group },
                    yes,
                )
                .await?;
            }
            HfsCommand::Untar {
                source,
                destination,
                archive,
                yes,
            } => {
                let archive = tokio::fs::read(&archive)
                    .await
                    .with_context(|| format!("failed to read {}", archive.display()))?;
                edit_hfs(
                    &kit,
                    output,
                    source,
                    destination,
                    HfsMutation::Untar { archive },
                    yes,
                )
                .await?;
            }
        },
        Command::Firmware {
            command: FirmwareCommand::Image { command },
        } => match command {
            ImageCommand::Extract {
                source,
                destination,
                key,
                iv,
            } => {
                kit.extract_image_payload(source, destination, image_cipher(key, iv)?)
                    .await?;
                write_status(output, "extracted-image-payload")?;
            }
            ImageCommand::Replace {
                source,
                payload,
                destination,
                key,
                iv,
                yes,
            } => {
                confirm("write the image container", yes)?;
                kit.replace_image_payload(source, payload, destination, image_cipher(key, iv)?)
                    .await?;
                write_status(output, "replaced-image-payload")?;
            }
            ImageCommand::PatchIboot32 {
                source,
                destination,
                boot_args,
                env_boot_args,
                cmd_handler,
                debug,
                ticket,
                local_boot,
                remote_boot,
                boot_partition,
                boot_partition9,
                boot_ramdisk,
                setenv,
                disable_kaslr,
                bgcolor,
                logo,
                logo4,
                jump_iboot_433,
                dualboot,
                yes,
            } => {
                confirm("write the patched iBoot image", yes)?;
                let handler = cmd_handler
                    .map(|value| {
                        let (command, pointer) = value
                            .split_once('=')
                            .ok_or_else(|| anyhow!("command handler must use CMD=PTR"))?;
                        let pointer = parse_integer(pointer)
                            .map_err(|error| anyhow!("invalid handler pointer: {error}"))?
                            as u32;
                        Ok::<_, anyhow::Error>((command.to_owned(), pointer))
                    })
                    .transpose()?;
                let boot_mode = if local_boot {
                    Some(BootMode::Local)
                } else if remote_boot {
                    Some(BootMode::Remote)
                } else {
                    None
                };
                let boot_partition = if boot_partition9 {
                    Some(BootPartition::Ios9OrLater)
                } else if boot_partition {
                    Some(BootPartition::Standard)
                } else {
                    None
                };
                let options = Iboot32PatchOptions {
                    boot_args,
                    env_boot_args,
                    command_handler: handler,
                    debug,
                    ticket,
                    boot_mode,
                    boot_partition,
                    boot_ramdisk,
                    setenv,
                    disable_kaslr,
                    bgcolor,
                    logo,
                    logo4,
                    jump_iboot_433,
                    dualboot,
                    skip_rsa: false,
                };
                kit.patch_iboot32(source, destination, options).await?;
                write_status(output, "patched-iboot32")?;
            }
        },
        Command::Firmware {
            command:
                FirmwareCommand::DecryptDmg {
                    source,
                    destination,
                    key,
                    yes,
                },
        } => {
            confirm("write the decrypted disk image", yes)?;
            let key = DmgFirmwareKey::from_hex(&key).context("invalid firmware DMG key")?;
            kit.decrypt_firmware_dmg(source, destination, key)
                .await
                .context("failed to decrypt firmware DMG")?;
            write_status(output, "decrypted-dmg")?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::Build {
                    source,
                    destination,
                    replacements,
                    removals,
                    yes,
                },
        } => {
            confirm("write the custom IPSW", yes)?;
            let mut data = Vec::with_capacity(replacements.len());
            for replacement in replacements {
                let (entry, path) = replacement
                    .split_once('=')
                    .ok_or_else(|| anyhow!("replacement must use ENTRY=FILE"))?;
                let path = PathBuf::from(path);
                data.push((
                    entry.to_owned(),
                    tokio::fs::read(&path)
                        .await
                        .with_context(|| format!("failed to read {}", path.display()))?,
                ));
            }
            let summary = kit
                .build_custom_ipsw(source, destination, data, removals)
                .await
                .context("failed to build custom IPSW")?;
            write_firmware(output, &summary)?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::BuildRootfs {
                    source,
                    destination,
                    board,
                    behavior,
                    key,
                    grow,
                    additions,
                    removals,
                    recursive,
                    directories,
                    moves,
                    modes,
                    owners,
                    archives,
                    yes,
                },
        } => {
            confirm("write the custom root filesystem IPSW", yes)?;
            let mut mutations = Vec::new();
            if let Some(size) = grow {
                mutations.push(HfsMutation::Grow { size });
            }
            for path in directories {
                mutations.push(HfsMutation::CreateDirectory { path });
            }
            for addition in additions {
                let (path, file) = addition
                    .split_once('=')
                    .ok_or_else(|| anyhow!("HFS addition must use HFS_PATH=FILE"))?;
                let file = PathBuf::from(file);
                let data = tokio::fs::read(&file)
                    .await
                    .with_context(|| format!("failed to read {}", file.display()))?;
                mutations.push(HfsMutation::AddFile {
                    path: path.to_owned(),
                    data,
                });
            }
            for path in removals {
                mutations.push(HfsMutation::Remove { path, recursive });
            }
            for value in moves {
                let (source, destination) = value
                    .split_once('=')
                    .ok_or_else(|| anyhow!("HFS move must use SOURCE=DESTINATION"))?;
                mutations.push(HfsMutation::Move {
                    source: source.to_owned(),
                    destination: destination.to_owned(),
                });
            }
            for value in modes {
                let (path, mode) = value
                    .split_once('=')
                    .ok_or_else(|| anyhow!("HFS mode must use HFS_PATH=MODE"))?;
                let mode = u16::from_str_radix(mode.trim_start_matches("0o"), 8)
                    .context("HFS mode must be octal")?;
                mutations.push(HfsMutation::Chmod {
                    path: path.to_owned(),
                    mode,
                });
            }
            for value in owners {
                let (path, owner) = value
                    .split_once('=')
                    .ok_or_else(|| anyhow!("HFS owner must use HFS_PATH=UID:GID"))?;
                let (owner, group) = owner
                    .split_once(':')
                    .ok_or_else(|| anyhow!("HFS owner must use UID:GID"))?;
                mutations.push(HfsMutation::Chown {
                    path: path.to_owned(),
                    owner: owner.parse().context("HFS owner must be an integer")?,
                    group: group.parse().context("HFS group must be an integer")?,
                });
            }
            for archive in archives {
                mutations.push(HfsMutation::Untar {
                    archive: tokio::fs::read(&archive)
                        .await
                        .with_context(|| format!("failed to read {}", archive.display()))?,
                });
            }
            let mut request =
                CustomRootfsRequest::new(source, destination, board, behavior.into(), mutations);
            if let Some(key) = key {
                request = request.with_firmware_key(
                    DmgFirmwareKey::from_hex(&key).context("invalid firmware DMG key")?,
                );
            }
            let summary = kit
                .build_custom_rootfs_ipsw(request)
                .await
                .context("failed to build custom root filesystem IPSW")?;
            write_firmware(output, &summary)?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::MultipartPrepare {
                    device,
                    board,
                    target_ipsw,
                    custom_ipsw,
                    base_ipsw,
                    nor_ipsw,
                    nor_url,
                    ticket,
                    part1,
                    part2,
                    cache_dir,
                    asr_patch,
                    exploit,
                    disable_bbupdate,
                    ipsw_verbose,
                    bootargs,
                    iboot_output,
                    skip_first,
                },
        } => {
            let nor_source = match (nor_ipsw, nor_url) {
                (Some(path), None) => NorSource::Local(path),
                (None, Some(url)) => NorSource::Remote(url),
                _ => {
                    return Err(anyhow!(
                        "exactly one of --nor-ipsw or --nor-url is required"
                    ));
                }
            };
            let cache_root = match cache_dir {
                Some(path) => path,
                None => config.artifact_cache_dir()?,
            };
            let mut request = MultipartPrepareRequest::new(
                device,
                board,
                target_ipsw,
                custom_ipsw,
                base_ipsw,
                nor_source,
                ticket,
                part1,
                part2,
                cache_root,
            )
            .with_disable_baseband_update(disable_bbupdate)
            .with_verbose_boot_args(ipsw_verbose)
            .with_skip_first(skip_first);
            if let Some(args) = bootargs {
                request = request.with_boot_args(args);
            }
            if let Some(path) = iboot_output {
                request = request.with_iboot_output(path);
            }
            if let Some(path) = asr_patch {
                request = request.with_asr_patch(path);
            }
            if let Some(path) = exploit {
                request = request.with_exploit(path);
            }
            let summary = kit
                .prepare_multipart_ipsw(request)
                .await
                .context("failed to build the multipart custom IPSWs")?;
            info!(part1 = %summary.part1().path().display(), "part 1 (NOR flash) IPSW built");
            write_firmware(output, summary.part1())?;
            info!(part2 = %summary.part2().path().display(), "part 2 (multipatch) IPSW built");
            write_firmware(output, summary.part2())?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::PowderPrepare {
                    device,
                    board,
                    target_ipsw,
                    base_ipsw,
                    apticket,
                    jailbreak,
                    openssh,
                    no_openssh,
                    memory,
                    ipsw_verbose,
                    bootargs,
                    disable_bbupdate,
                    activation_records,
                    iboot,
                    output_ipsw,
                    cache_dir,
                },
        } => {
            if memory {
                debug!("--memory is inherent to the in-memory Rust builder");
            }
            let cache_root = match cache_dir {
                Some(path) => path,
                None => config.artifact_cache_dir()?,
            };
            let mut request = PowderPrepareRequest::new(
                device.clone(),
                board,
                target_ipsw,
                output_ipsw.clone(),
                cache_root,
            )
            .with_jailbreak(jailbreak)
            .with_openssh(openssh && !no_openssh)
            .with_verbose_boot_args(ipsw_verbose)
            .with_disable_baseband_update(disable_bbupdate);
            if let Some(args) = bootargs {
                request = request.with_boot_args(args);
            }
            if let Some(base) = base_ipsw {
                request = request.with_base(base);
            }
            if let Some(path) = apticket {
                let ticket =
                    SigningTicket::open(&path).context("failed to read the -apticket SHSH blob")?;
                request = request.with_apticket(extract_apticket_der(&ticket));
            }
            if let Some(path) = activation_records {
                let name = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "activation.tar".to_owned());
                let data = tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("failed to read {}", path.display()))?;
                request = request.with_extra_tars(vec![(name, data)]);
            }
            if let Some(path) = iboot {
                let data = tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("failed to read {}", path.display()))?;
                // Upstream merges the patched iBoot as iBEC on iPad1,1 and as
                // iBoot elsewhere (restore.sh:5701 ipsw_prepare_powder).
                let name = if device.as_str() == "iPad1,1" {
                    "iBEC"
                } else {
                    "iBoot"
                };
                request = request.with_iboot_sidecar(name, data);
            }
            let plan = kit
                .plan_powder_ipsw(request)
                .await
                .context("failed to plan the powder custom IPSW")?;
            info!(
                version = %plan.version(),
                build = %plan.build_id(),
                mode = ?plan.mode(),
                "powder build planned"
            );
            consume_operation(output, kit.execute_powder_prepare(plan)).await?;
            let summary = kit
                .inspect_firmware(output_ipsw)
                .context("failed to inspect the built powder IPSW")?;
            write_firmware(output, &summary)?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::ClassicPrepare {
                    device,
                    board,
                    target_ipsw,
                    jailbreak,
                    openssh,
                    no_openssh,
                    hacktivate,
                    beta,
                    old_bootrom_24kpwn,
                    disable_bbupdate,
                    activation_records,
                    baseband,
                    iboot,
                    latest_version,
                    memory,
                    output_ipsw,
                    cache_dir,
                },
        } => {
            if memory {
                debug!("--memory is inherent to the in-memory Rust builder");
            }
            let cache_root = match cache_dir {
                Some(path) => path,
                None => config.artifact_cache_dir()?,
            };
            let mut request = ClassicPrepareRequest::new(
                device.clone(),
                board,
                target_ipsw,
                output_ipsw.clone(),
                cache_root,
            )
            .with_jailbreak(jailbreak)
            .with_openssh(openssh && !no_openssh)
            .with_hacktivate(hacktivate)
            .with_beta(beta)
            .with_24kpwn_old_bootrom(old_bootrom_24kpwn)
            .with_disable_baseband_update(disable_bbupdate);
            if let Some(version) = latest_version {
                request = request.with_latest_version(IosVersion::from(version.as_str()));
            }
            // Upstream ExtraArgs order: the baseband tar, then the
            // activation records tar.
            let mut extra_tars = Vec::new();
            for (path, fallback) in [
                (baseband, "baseband.tar"),
                (activation_records, "activation.tar"),
            ] {
                if let Some(path) = path {
                    let name = path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| fallback.to_owned());
                    let data = tokio::fs::read(&path)
                        .await
                        .with_context(|| format!("failed to read {}", path.display()))?;
                    extra_tars.push((name, data));
                }
            }
            if !extra_tars.is_empty() {
                request = request.with_extra_tars(extra_tars);
            }
            if let Some(path) = iboot {
                let data = tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("failed to read {}", path.display()))?;
                // Upstream merges the patched iBoot as iBEC on iPad1,1 and as
                // iBoot elsewhere (restore.sh ipsw_prepare_iboot).
                let name = if device.as_str() == "iPad1,1" {
                    "iBEC"
                } else {
                    "iBoot"
                };
                request = request.with_iboot_sidecar(name, data);
            }
            let plan = kit
                .plan_classic_ipsw(request)
                .await
                .context("failed to plan the classic custom IPSW")?;
            info!(
                version = %plan.version(),
                build = %plan.build_id(),
                old = plan.old(),
                "classic build planned"
            );
            consume_operation(output, kit.execute_classic_prepare(plan)).await?;
            let summary = kit
                .inspect_firmware(output_ipsw)
                .context("failed to inspect the built classic IPSW")?;
            write_firmware(output, &summary)?;
        }
        Command::Firmware {
            command:
                FirmwareCommand::FourThreePrepare {
                    device,
                    target_ipsw,
                    base_ipsw,
                    bootchain_ipsw,
                    bootchain_url,
                    output_ipsw,
                    components_dir,
                    cache_dir,
                },
        } => {
            let bootchain_source = match (bootchain_ipsw, bootchain_url) {
                (Some(path), None) => FourThreeComponentSource::Local(path),
                (None, Some(url)) => FourThreeComponentSource::Remote(url),
                _ => {
                    return Err(anyhow!(
                        "exactly one of --bootchain-ipsw or --bootchain-url is required"
                    ));
                }
            };
            let cache_root = match cache_dir {
                Some(path) => path,
                None => config.artifact_cache_dir()?,
            };
            let outcome = kit
                .prepare_fourthree_ipsw(FourThreePrepareRequest::new(
                    device,
                    target_ipsw,
                    base_ipsw,
                    bootchain_source,
                    output_ipsw,
                    components_dir,
                    cache_root,
                ))
                .await
                .context("failed to build the FourThree custom IPSW and components")?;
            info!(ipsw = %outcome.ipsw().path().display(), "FourThree custom IPSW built");
            write_firmware(output, outcome.ipsw())?;
            info!(
                kernelcache = %outcome.kernelcache().display(),
                llb = %outcome.llb().display(),
                rootfs = %outcome.rootfs_dmg().display(),
                "FourThree dualboot components built"
            );
        }
        Command::Restore {
            command:
                RestoreCommand::Plan {
                    device,
                    board,
                    ecid,
                    firmware,
                    behavior,
                    ticket,
                    onboard_ticket,
                    skip_blob,
                    baseband,
                    no_baseband,
                    sep,
                    no_sep,
                    exploit,
                    set_nonce,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let ticket = if skip_blob {
                TicketPolicy::Skip
            } else if onboard_ticket {
                TicketPolicy::Onboard
            } else if let Some(ticket) = ticket {
                TicketPolicy::Provided(ticket)
            } else {
                TicketPolicy::Signed
            };
            let baseband = if no_baseband {
                BasebandPolicy::None
            } else if let Some(baseband) = baseband {
                BasebandPolicy::Provided(baseband)
            } else {
                BasebandPolicy::Auto
            };
            let sep = if no_sep {
                SepPolicy::None
            } else {
                sep.map_or(SepPolicy::Auto, SepPolicy::Provided)
            };
            let plan = kit
                .plan_restore(RestoreRequest {
                    device,
                    firmware,
                    behavior: behavior.into(),
                    ticket,
                    baseband,
                    sep,
                    exploit: exploit.into(),
                    nonce: nonce_policy(set_nonce),
                })
                .context("failed to resolve restore plan")?;
            write_restore_plan(output, &plan)?;
        }
        Command::Restore {
            command:
                RestoreCommand::Execute {
                    device,
                    board,
                    ecid,
                    firmware,
                    ticket,
                    skip_blob,
                    work_dir,
                    behavior,
                    exploit,
                    limera1n_payload,
                    baseband,
                    no_baseband,
                    sep,
                    no_sep,
                    flash_version_1,
                    set_nonce,
                    yes,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let plan = kit.plan_restore(RestoreRequest {
                device,
                firmware,
                behavior: behavior.into(),
                ticket: if skip_blob {
                    TicketPolicy::Skip
                } else {
                    ticket
                        .clone()
                        .map_or(TicketPolicy::Signed, TicketPolicy::Provided)
                },
                baseband: if no_baseband {
                    BasebandPolicy::None
                } else if let Some(baseband) = baseband {
                    BasebandPolicy::Provided(baseband)
                } else {
                    BasebandPolicy::Auto
                },
                sep: if no_sep {
                    SepPolicy::None
                } else {
                    sep.map_or(SepPolicy::Auto, SepPolicy::Provided)
                },
                exploit: exploit.into(),
                nonce: nonce_policy(set_nonce),
            })?;
            confirm(
                &format!(
                    "erase/restore the selected device with plan {}",
                    plan.id().as_str()
                ),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit"));
            let mut request = if skip_blob {
                RestoreExecutionRequest::skip_blob(plan, consent, work_directory)
            } else if let Some(ticket) = ticket {
                RestoreExecutionRequest::new(
                    plan,
                    consent,
                    SigningTicket::open(&ticket).context("failed to read signing ticket")?,
                    work_directory,
                )
            } else {
                RestoreExecutionRequest::signed(plan, consent, work_directory)
            }
            .with_flash_version_1(flash_version_1);
            if let Some(path) = limera1n_payload {
                request = request.with_limera1n_payload(
                    tokio::fs::read(&path)
                        .await
                        .with_context(|| format!("failed to read {}", path.display()))?,
                );
            }
            consume_operation(output, kit.execute_restore(request)).await?;
        }
        Command::Restore {
            command:
                RestoreCommand::Multipart {
                    device,
                    board,
                    ecid,
                    part1,
                    part2,
                    ticket,
                    work_dir,
                    exploit,
                    limera1n_payload,
                    no_baseband,
                    skip_first,
                    part2_ticket,
                    yes,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let part1_plan = kit
                .plan_restore(RestoreRequest {
                    device: device.clone(),
                    firmware: part1,
                    behavior: RestoreBehavior::Erase,
                    ticket: TicketPolicy::Provided(ticket.clone()),
                    // The part 1 ramdisk options disable the baseband update.
                    baseband: BasebandPolicy::None,
                    sep: SepPolicy::Auto,
                    exploit: exploit.into(),
                    nonce: NoncePolicy::Manual,
                })
                .context("failed to resolve the part 1 restore plan")?;
            let part2_plan = kit
                .plan_restore(RestoreRequest {
                    device,
                    firmware: part2,
                    behavior: RestoreBehavior::Erase,
                    // The multipatched boot chain is RSA-patched; part 2
                    // restores without a blob on the pwned device by default.
                    // With --part2-ticket the blob is supplied to part 2 as
                    // well, matching upstream's `-w` (restore.sh:6596-6616).
                    ticket: if part2_ticket {
                        TicketPolicy::Provided(ticket.clone())
                    } else {
                        TicketPolicy::Skip
                    },
                    baseband: if no_baseband {
                        BasebandPolicy::None
                    } else {
                        BasebandPolicy::Auto
                    },
                    sep: SepPolicy::Auto,
                    exploit: exploit.into(),
                    nonce: NoncePolicy::Manual,
                })
                .context("failed to resolve the part 2 restore plan")?;
            confirm(
                &format!(
                    "erase/restore the selected device with multipart plans {} and {}",
                    part1_plan.id().as_str(),
                    part2_plan.id().as_str()
                ),
                yes,
            )?;
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit"));
            let mut part1_request = RestoreExecutionRequest::new(
                part1_plan.clone(),
                part1_plan.confirm_destructive(),
                SigningTicket::open(&ticket).context("failed to read signing ticket")?,
                work_directory.clone(),
            );
            let mut part2_request = if part2_ticket {
                RestoreExecutionRequest::new(
                    part2_plan.clone(),
                    part2_plan.confirm_destructive(),
                    SigningTicket::open(&ticket).context("failed to read signing ticket")?,
                    work_directory,
                )
            } else {
                RestoreExecutionRequest::skip_blob(
                    part2_plan.clone(),
                    part2_plan.confirm_destructive(),
                    work_directory,
                )
            };
            if let Some(path) = limera1n_payload {
                let payload = tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("failed to read {}", path.display()))?;
                part1_request = part1_request.with_limera1n_payload(payload.clone());
                part2_request = part2_request.with_limera1n_payload(payload);
            }
            consume_operation(
                output,
                kit.execute_multipart_restore(
                    MultipartRestoreRequest::new(part1_request, part2_request)
                        .with_skip_first(skip_first),
                ),
            )
            .await?;
        }
        Command::Restore {
            command:
                RestoreCommand::Powder {
                    device,
                    board,
                    ecid,
                    firmware,
                    ticket,
                    latest_ipsw,
                    cpid,
                    bdid,
                    pwn,
                    ticket_dir,
                    work_dir,
                    limera1n_payload,
                    no_baseband,
                    yes,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let ticket = if let Some(ticket) = ticket {
                PowderTicketSource::Provided(ticket)
            } else if let Some(latest_ipsw) = latest_ipsw {
                let destination_dir = match ticket_dir {
                    Some(path) => path,
                    None => config.artifact_cache_dir()?.join("shsh"),
                };
                PowderTicketSource::FetchLatest {
                    firmware: latest_ipsw,
                    destination_dir,
                    chip_id: cpid.expect("clap requires --cpid with --latest-ipsw"),
                    board_id: bdid.expect("clap requires --bdid with --latest-ipsw"),
                }
            } else {
                return Err(anyhow!(
                    "one of --ticket (base-version blob) or --latest-ipsw (A4 TSS fetch) is required"
                ));
            };
            // Upstream's menu order (device_buttons, restore.sh:6435-6474):
            // kDFU recommended on A5/A5X/A6/A6X, pwnDFU first on A4.
            let pwn = pwn.map_or_else(
                || match device.soc() {
                    Soc::A5 | Soc::A5x | Soc::A6 | Soc::A6x => PowderPwnMethod::Kdfu,
                    _ => PowderPwnMethod::PwnDfu,
                },
                PowderPwnMethod::from,
            );
            let mut plan = kit
                .plan_powder_restore(
                    PowderRestoreRequest::new(device, firmware, ticket, pwn).with_baseband(
                        if no_baseband {
                            BasebandPolicy::None
                        } else {
                            BasebandPolicy::Auto
                        },
                    ),
                )
                .await
                .context("failed to plan the powder restore")?;
            if let Some(version) = plan.ticket_version() {
                info!(
                    ticket = %plan.ticket_path().display(),
                    %version,
                    "fetched the latest-version ticket"
                );
            }
            confirm(
                &format!(
                    "erase/restore the selected device with powder plan {}",
                    plan.id().as_str()
                ),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            if let Some(path) = limera1n_payload {
                plan = plan.with_limera1n_payload(
                    tokio::fs::read(&path)
                        .await
                        .with_context(|| format!("failed to read {}", path.display()))?,
                );
            }
            let work_directory = work_dir
                .or_else(|| config.storage.work_dir.clone())
                .unwrap_or_else(|| std::env::temp_dir().join("legacy-ios-kit"));
            consume_operation(
                output,
                kit.execute_powder_restore(plan, consent, work_directory),
            )
            .await?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Boot {
                    device,
                    board,
                    ecid,
                    ibss,
                    ibec,
                    ramdisk,
                    device_tree,
                    trust_cache,
                    kernel,
                    ticket,
                    boot_args,
                    exploit,
                    limera1n_payload,
                    yes,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let plan = kit
                .plan_ramdisk_boot(RamdiskBootRequest {
                    device,
                    ibss,
                    ibec,
                    ramdisk,
                    device_tree,
                    trust_cache,
                    kernel,
                    ticket,
                    boot_args,
                    exploit: exploit.into(),
                })
                .context("failed to resolve ramdisk boot plan")?;
            confirm(
                &format!("boot the ramdisk with plan {}", plan.id().as_str()),
                yes,
            )?;
            let consent = plan.confirm_destructive();
            let mut request = RamdiskBootExecutionRequest::new(plan, consent);
            if let Some(path) = limera1n_payload {
                request = request.with_limera1n_payload(
                    tokio::fs::read(&path)
                        .await
                        .with_context(|| format!("failed to read {}", path.display()))?,
                );
            }
            consume_operation(output, kit.execute_ramdisk_boot(request)).await?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Build {
                    firmware,
                    destination,
                    board,
                    behavior,
                    key,
                    iv,
                    grow,
                    additions,
                    removals,
                    recursive,
                    archives,
                    yes,
                },
        } => {
            confirm("write the patched restore ramdisk", yes)?;
            let mut mutations = Vec::new();
            if let Some(size) = grow {
                mutations.push(HfsMutation::Grow { size });
            }
            for addition in additions {
                let (path, file) = addition
                    .split_once('=')
                    .ok_or_else(|| anyhow!("ramdisk addition must use HFS_PATH=FILE"))?;
                let file = PathBuf::from(file);
                mutations.push(HfsMutation::AddFile {
                    path: path.to_owned(),
                    data: tokio::fs::read(&file)
                        .await
                        .with_context(|| format!("failed to read {}", file.display()))?,
                });
            }
            for path in removals {
                mutations.push(HfsMutation::Remove { path, recursive });
            }
            for archive in archives {
                mutations.push(HfsMutation::Untar {
                    archive: tokio::fs::read(&archive)
                        .await
                        .with_context(|| format!("failed to read {}", archive.display()))?,
                });
            }
            let mut request =
                RamdiskBuildRequest::new(firmware, destination, board, behavior.into(), mutations);
            if let Some(cipher) = image_cipher(key, iv)? {
                request = request.with_cipher(cipher);
            }
            let summary = kit
                .build_ramdisk(request)
                .await
                .context("failed to build restore ramdisk")?;
            write_ramdisk_build(output, &summary)?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Ssh {
                    device_id,
                    username,
                    host_key,
                    command,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let result = ssh
                .execute(&command.join(" "))
                .await
                .context("ramdisk SSH command failed")?;
            ssh.disconnect().await?;
            write_ssh_output(output, &result)?;
            if !result.success() {
                return Err(anyhow!(
                    "remote command exited with status {:?}",
                    result.exit_status()
                ));
            }
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Push {
                    source,
                    destination,
                    device_id,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("write the ramdisk file", yes)?;
            let data = tokio::fs::read(&source)
                .await
                .with_context(|| format!("failed to read {}", source.display()))?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.upload(&destination, &data).await?;
            ssh.disconnect().await?;
            write_status(output, "pushed-ramdisk-file")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Pull {
                    source,
                    destination,
                    device_id,
                    username,
                    host_key,
                    max_size,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let data = ssh.download(&source, max_size).await?;
            ssh.disconnect().await?;
            tokio::fs::write(&destination, data)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "pulled-ramdisk-file")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::DumpOnboard {
                    destination,
                    disk,
                    device_id,
                    username,
                    host_key,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let dump = ssh.read_prefix(&disk, 256, 0x4000).await?;
            ssh.disconnect().await?;
            let ticket = kit.convert_onboard_dump(&dump)?;
            ticket.save(&destination).await?;
            write_status(output, "saved-onboard-ticket")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::DumpActivation {
                    destination,
                    device_id,
                    username,
                    host_key,
                    ios_version,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let version = match ios_version {
                Some(version) => version,
                None => {
                    ssh.mount_filesystems(true).await?;
                    ssh.system_version()
                        .await
                        .context("failed to read the device iOS version")?
                }
            };
            ssh.mount_filesystems(false).await?;
            let dump = ssh.dump_activation_records(&version).await?;
            ssh.disconnect().await?;
            if !legacy_ios_kit::tar_contains_entry(&dump, "_record.plist") {
                warn!("dump contains no activation record plist");
            }
            tokio::fs::write(&destination, dump)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "saved-activation-records")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::DumpBaseband {
                    destination,
                    device_id,
                    username,
                    host_key,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.mount_filesystems(true).await?;
            let dump = ssh.dump_baseband().await?;
            ssh.disconnect().await?;
            if !legacy_ios_kit::tar_contains_entry(&dump, "bbticket.der") {
                warn!("dump contains no bbticket.der");
            }
            tokio::fs::write(&destination, dump)
                .await
                .with_context(|| format!("failed to write {}", destination.display()))?;
            write_status(output, "saved-baseband-dump")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Trollstore {
                    device_id,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("install TrollStore into the Tips app", yes)?;
            let cache = config.artifact_cache_dir()?;
            let tar_path = kit
                .fetch_resource(&ResourceId::new("trollstore-tar"), &cache)
                .await?;
            let helper_path = kit
                .fetch_resource(&ResourceId::new("trollstore-persistence-helper"), &cache)
                .await?;
            let tar = tokio::fs::read(&tar_path).await?;
            let helper = legacy_ios_kit::tar_extract_entry(&tar, "TrollStore.app/trollstorehelper")
                .ok_or_else(|| anyhow!("trollstorehelper not found in TrollStore.tar"))?;
            let persistence = tokio::fs::read(&helper_path).await?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            kit.install_trollstore(&ssh, &persistence, &helper)
                .await
                .context("TrollStore installation failed")?;
            ssh.disconnect().await?;
            write_status(output, "installed-trollstore")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::NvramClear {
                    device_id,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("clear the device NVRAM", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.clear_nvram().await?;
            ssh.disconnect().await?;
            write_status(output, "cleared-nvram")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::FixDatetime {
                    device_id,
                    username,
                    host_key,
                },
        } => {
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| anyhow!("system clock error: {error}"))?
                .as_secs();
            ssh.fix_datetime(epoch).await?;
            ssh.disconnect().await?;
            write_status(output, "fixed-datetime")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Erase9 {
                    device_id,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("mark the device for erase on next boot (iOS 9+)", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.erase_ios9().await?;
            ssh.disconnect().await?;
            write_status(output, "erase-armed")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Erase78 {
                    device_id,
                    username,
                    host_key,
                    yes,
                },
        } => {
            confirm("erase all content and settings (iOS 7/8)", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.erase_ios78().await?;
            write_status(output, "erase-triggered")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Bootstrap {
                    device_id,
                    username,
                    host_key,
                    ios_version,
                    yes,
                },
        } => {
            confirm("install the jailbreak bootstrap on the device", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let version = match ios_version {
                Some(version) => version,
                None => {
                    ssh.execute("/sbin/mount_hfs /dev/disk0s1s1 /mnt1").await?;
                    ssh.system_version()
                        .await
                        .context("failed to read the device iOS version")?
                }
            };
            let selection = legacy_ios_kit::bootstrap_selection(&version)
                .ok_or_else(|| anyhow!("bootstrap supports 64-bit iOS 7/8/9, found {version}"))?;
            let cache = config.artifact_cache_dir()?;
            let fetch = async |id: &str, gz: bool| -> Result<Vec<u8>> {
                let path = kit.fetch_resource(&ResourceId::new(id), &cache).await?;
                let data = tokio::fs::read(&path).await?;
                Ok(if gz {
                    legacy_ios_kit::gunzip(&data)?
                } else {
                    data
                })
            };
            let packages = legacy_ios_kit::BootstrapPackages {
                freeze: fetch("jailbreak-bootstrap-freeze", true).await?,
                openssh: fetch("jailbreak-openssh", true).await?,
                openssl: fetch("jailbreak-openssl", true).await?,
                launchctl: if selection.needs_launchctl {
                    Some(fetch("jailbreak-launchctl", false).await?)
                } else {
                    None
                },
                pangu_loader: if selection.needs_pangu_loader {
                    Some(fetch("jailbreak-pangu93-loader", false).await?)
                } else {
                    None
                },
                nopatcyh: if selection.needs_nopatcyh {
                    Some(fetch("jailbreak-nopatcyh", false).await?)
                } else {
                    None
                },
            };
            kit.install_bootstrap(&ssh, &version, &packages)
                .await
                .context("bootstrap installation failed")?;
            ssh.disconnect().await?;
            write_status(output, "installed-bootstrap")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Untether7 {
                    device_id,
                    username,
                    host_key,
                    ios_version,
                    stash,
                    yes,
                },
        } => {
            confirm("install the iOS 7 untether on the device", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            let version = match ios_version {
                Some(version) => version,
                None => {
                    ssh.execute("/sbin/mount_hfs /dev/disk0s1s1 /mnt1").await?;
                    ssh.system_version()
                        .await
                        .context("failed to read the device iOS version")?
                }
            };
            let resource = legacy_ios_kit::select_untether7(&version)
                .ok_or_else(|| anyhow!("no iOS 7 untether package for version {version}"))?;
            let path = kit
                .fetch_resource(&resource, config.artifact_cache_dir()?)
                .await?;
            let untether = tokio::fs::read(&path).await?;
            kit.install_untether7(&ssh, &untether, stash)
                .await
                .context("untether installation failed")?;
            ssh.disconnect().await?;
            write_status(output, "installed-untether")?;
        }
        Command::Ramdisk {
            command:
                RamdiskCommand::Jailbreak {
                    device_id,
                    username,
                    host_key,
                    device,
                    ios_version,
                    build,
                    yes,
                },
        } => {
            confirm("jailbreak the device", yes)?;
            let ssh = connect_ramdisk_ssh(&kit, device_id, &username, host_key).await?;
            ssh.mount_filesystems(true)
                .await
                .context("failed to mount the device root filesystem")?;
            let version = match ios_version {
                Some(version) => version,
                None => ssh
                    .system_version()
                    .await
                    .context("failed to read the device iOS version")?,
            };
            let build = match build {
                Some(build) => build,
                None => ssh
                    .system_build()
                    .await
                    .context("failed to read the device iOS build")?,
            };
            let product_type = device.as_str();
            let plan = legacy_ios_kit::JailbreakPlan::for_device(product_type, &version, &build)
                .ok_or_else(|| {
                    anyhow!(
                        "iOS {version} ({build}) on {product_type} is not supported for the SSH ramdisk jailbreak"
                    )
                })?;
            info!(%product_type, %version, %build, "resolved jailbreak plan");
            let cache = config.artifact_cache_dir()?;
            let fetch = async |id: &ResourceId, gz: bool| -> Result<Vec<u8>> {
                let path = kit.fetch_resource(id, &cache).await?;
                let data = tokio::fs::read(&path).await?;
                Ok(if gz {
                    legacy_ios_kit::gunzip(&data)?
                } else {
                    data
                })
            };
            let fetch_opt = async |id: &str, needed: bool| -> Result<Option<Vec<u8>>> {
                if needed {
                    Ok(Some(fetch(&ResourceId::new(id), false).await?))
                } else {
                    Ok(None)
                }
            };
            let packages = legacy_ios_kit::JailbreakPackages {
                freeze: fetch(&plan.freeze_resource(), true).await?,
                untether: match plan.untether() {
                    Some(untether) => Some(fetch(&untether.resource_id(), false).await?),
                    None => None,
                },
                daibutsu_move: fetch_opt("jailbreak-daibutsu-move", plan.needs_daibutsu_move())
                    .await?,
                fstab: fetch(&plan.fstab().resource_id(), false).await?,
                cydia_substrate: fetch_opt(
                    "jailbreak-cydiasubstrate",
                    plan.needs_cydia_substrate(),
                )
                .await?,
                launchctl: fetch_opt("jailbreak-launchctl", plan.needs_launchctl_zebra()).await?,
                zebra: fetch_opt("jailbreak-zebra", plan.needs_launchctl_zebra()).await?,
                cydia_http_patch: fetch_opt(
                    "jailbreak-cydiahttpatch",
                    plan.needs_cydia_http_patch(),
                )
                .await?,
                lukezgd: fetch_opt("jailbreak-lukezgd", plan.needs_lukezgd()).await?,
                nopatcyh: fetch_opt("jailbreak-nopatcyh", plan.removes_patcyh()).await?,
            };
            kit.install_jailbreak(&ssh, &plan, &packages)
                .await
                .context("jailbreak installation failed")?;
            write_status(output, "jailbroken")?;
        }
        Command::Shsh {
            command:
                ShshCommand::Save {
                    firmware,
                    board,
                    ecid,
                    cpid,
                    bdid,
                    behavior,
                    image_format,
                    ap_nonce,
                    sep_nonce,
                    destination,
                },
        } => {
            let mut request = ShshRequest::new(firmware, board, behavior.into(), ecid, bdid, cpid)
                .with_img4_support(image_format == ImageFormatArg::Img4);
            if let Some(nonce) = ap_nonce {
                request = request.with_ap_nonce(nonce);
            }
            if let Some(nonce) = sep_nonce {
                request = request.with_sep_nonce(nonce);
            }
            let summary = kit
                .save_shsh(&request, destination)
                .await
                .context("failed to save signing ticket")?;
            write_shsh(output, &summary)?;
        }
    }
    Ok(())
}

async fn connect_ramdisk_ssh(
    kit: &LegacyIosKit,
    device_id: Option<u32>,
    username: &str,
    host_key: Option<String>,
) -> Result<RamdiskSsh> {
    let password = SshPassword::new(
        rpassword::prompt_password("SSH password: ").context("failed to read SSH password")?,
    );
    let target = device_id.map_or(SshTarget::OnlyUsbDevice, SshTarget::DeviceId);
    let host_key = host_key.map_or_else(
        || {
            warn!("accepting ephemeral ramdisk SSH host key");
            HostKeyPolicy::AcceptEphemeral
        },
        HostKeyPolicy::Sha256,
    );
    kit.devices()
        .ramdisk_ssh(target, username, &password, host_key)
        .await
        .context("failed to connect to ramdisk SSH")
}

const fn nonce_policy(set_nonce: bool) -> NoncePolicy {
    if set_nonce {
        NoncePolicy::Auto
    } else {
        NoncePolicy::Manual
    }
}

fn parse_integer(value: &str) -> Result<u64, String> {
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse(), |value| u64::from_str_radix(value, 16))
        .map_err(|_| format!("invalid integer: {value}"))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| format!("invalid hexadecimal data: {value}"))
}

fn write_shsh(format: OutputFormat, summary: &ShshSummary) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, summary)?;
            writeln!(output)?;
        }
        OutputFormat::Human => writeln!(
            output,
            "Saved {} {} ticket for {} to {}",
            summary.product_version(),
            summary.build_id(),
            summary.board_config(),
            summary.path().display()
        )?,
    }
    Ok(())
}

fn write_config(format: OutputFormat, config: &AppConfig) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, config)?;
            writeln!(output)?;
        }
        OutputFormat::Human => write!(output, "{}", toml::to_string_pretty(config)?)?,
    }
    Ok(())
}

fn write_ssh_output(format: OutputFormat, result: &SshCommandOutput) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({
                    "stdout": String::from_utf8_lossy(result.stdout()),
                    "stderr": String::from_utf8_lossy(result.stderr()),
                    "exit_status": result.exit_status(),
                }),
            )?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            io::stdout().lock().write_all(result.stdout())?;
            io::stderr().lock().write_all(result.stderr())?;
        }
    }
    Ok(())
}

async fn consume_operation(format: OutputFormat, mut handle: OperationHandle) -> Result<()> {
    let mut cancellation_requested = false;
    loop {
        tokio::select! {
            event = handle.next_event() => {
                let Some(event) = event else {
                    return if cancellation_requested {
                        Err(anyhow!("operation cancelled"))
                    } else {
                        Err(anyhow!("operation ended without a result"))
                    };
                };
                match event? {
                    OperationEvent::PhaseStarted { phase, cancellation } => {
                        info!(?phase, ?cancellation, "operation phase started");
                    }
                    OperationEvent::Progress(progress) => {
                        debug!(
                            phase = ?progress.phase,
                            completed = progress.completed,
                            total = progress.total,
                            unit = ?progress.unit,
                            "operation progress"
                        );
                    }
                    OperationEvent::ModeChanged { mode } => info!(?mode, "device mode changed"),
                    OperationEvent::DeviceDisconnected => info!("device disconnected"),
                    OperationEvent::DeviceReconnected { device } => {
                        info!(mode = ?device.mode(), "device reconnected");
                    }
                    OperationEvent::ActionRequired { action, .. } => {
                        warn!(?action, "operation requires user action");
                    }
                    OperationEvent::Warning { message } => warn!(message, "operation warning"),
                    OperationEvent::CancellationDeferred { phase } => {
                        warn!(?phase, "cancellation deferred until safe point");
                    }
                    OperationEvent::Completed { outcome } => {
                        return write_operation_outcome(format, &outcome);
                    }
                }
            }
            result = tokio::signal::ctrl_c(), if !cancellation_requested => {
                result.context("failed to listen for Ctrl-C")?;
                cancellation_requested = true;
                handle.cancel();
                warn!("cancellation requested");
            }
        }
    }
}

fn write_operation_outcome(format: OutputFormat, outcome: &OperationOutcome) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, outcome)?;
            writeln!(output)?;
        }
        OutputFormat::Human => writeln!(output, "{}", outcome.summary)?,
    }
    Ok(())
}

fn write_data_list(format: OutputFormat, entries: &[String]) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, entries)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            for entry in entries {
                writeln!(output, "{entry}")?;
            }
        }
    }
    Ok(())
}

fn write_backup_outcome(format: OutputFormat, outcome: &BackupOutcome) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, outcome)?;
            writeln!(output)?;
        }
        OutputFormat::Human => writeln!(
            output,
            "Backed up {} files ({} bytes)",
            outcome.files(),
            outcome.bytes()
        )?,
    }
    Ok(())
}

fn write_file_info(format: OutputFormat, info: &DeviceFileInfo) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, info)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "Type: {:?}", info.kind())?;
            writeln!(output, "Size: {}", info.size())?;
            if let Some(target) = info.link_target() {
                writeln!(output, "Target: {target}")?;
            }
        }
    }
    Ok(())
}

fn write_storage_info(format: OutputFormat, info: &DeviceStorageInfo) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, info)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "Model: {}", info.model())?;
            writeln!(output, "Total: {}", info.total_bytes())?;
            writeln!(output, "Free: {}", info.free_bytes())?;
            writeln!(output, "Block size: {}", info.block_size())?;
        }
    }
    Ok(())
}

fn write_path(format: OutputFormat, path: &std::path::Path) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Human => writeln!(output, "{}", path.display())?,
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, &serde_json::json!({ "path": path }))?;
            writeln!(output)?;
        }
    }
    Ok(())
}

async fn edit_hfs(
    kit: &LegacyIosKit,
    output: OutputFormat,
    source: PathBuf,
    destination: PathBuf,
    mutation: HfsMutation,
    yes: bool,
) -> Result<()> {
    confirm("write the HFS+ image", yes)?;
    kit.edit_hfs(source, destination, vec![mutation]).await?;
    write_status(output, "edited-hfs-image")
}

fn image_cipher(key: Option<String>, iv: Option<String>) -> Result<Option<ImageCipher>> {
    match (key, iv) {
        (Some(key), Some(iv)) => Ok(Some(
            ImageCipher::from_hex(&key, &iv).context("invalid image cipher")?,
        )),
        (None, None) => Ok(None),
        _ => Err(anyhow!("image key and IV must be supplied together")),
    }
}

fn write_hfs_entries(format: OutputFormat, entries: &[HfsEntrySummary]) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, entries)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            for entry in entries {
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    entry.kind(),
                    entry.size(),
                    entry.name()
                )?;
            }
        }
    }
    Ok(())
}

fn write_hfs_stat(format: OutputFormat, stat: &HfsStatSummary) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, stat)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "CNID: {}", stat.cnid())?;
            writeln!(output, "Kind: {}", stat.kind())?;
            writeln!(output, "Size: {}", stat.size())?;
            writeln!(output, "Owner: {}", stat.owner())?;
            writeln!(output, "Group: {}", stat.group())?;
            writeln!(output, "Mode: {:06o}", stat.mode())?;
        }
    }
    Ok(())
}

fn write_ramdisk_build(format: OutputFormat, summary: &RamdiskBuildSummary) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, summary)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "Component: {}", summary.component_path())?;
            writeln!(output, "Destination: {}", summary.destination().display())?;
            writeln!(output, "Size: {}", summary.size())?;
        }
    }
    Ok(())
}

fn write_status(format: OutputFormat, status: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Human => writeln!(output, "{status}")?,
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, &serde_json::json!({ "status": status }))?;
            writeln!(output)?;
        }
    }
    Ok(())
}

fn write_syslog(format: OutputFormat, records: &[String]) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, records)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            for record in records {
                writeln!(output, "{record}")?;
            }
        }
    }
    Ok(())
}

fn write_recovery_info(
    format: OutputFormat,
    mode: legacy_ios_kit::DeviceMode,
    info: &RecoveryDeviceInfo,
) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(
                &mut output,
                &serde_json::json!({ "mode": mode, "device": info }),
            )?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "Mode: {mode}")?;
            writeln!(output, "CPID: {:#x}", info.effective_cpid())?;
            if let Some(ecid) = info.ecid() {
                writeln!(output, "ECID: {ecid}")?;
            }
            if let Some(srtg) = info.srtg() {
                writeln!(output, "SRTG: {srtg}")?;
            }
            if let Some(pwned) = info.pwned() {
                writeln!(output, "PWND: {pwned}")?;
            }
        }
    }
    Ok(())
}

fn write_apps(format: OutputFormat, apps: &[InstalledApp]) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, apps)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            for app in apps {
                writeln!(
                    output,
                    "{}  {}  {}",
                    app.bundle_id(),
                    app.version().unwrap_or("unknown version"),
                    app.name().unwrap_or("unnamed")
                )?;
            }
        }
    }
    Ok(())
}

fn confirm(action: &str, accepted: bool) -> Result<()> {
    if accepted {
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    write!(stdout, "Confirm {action} [y/N]: ")?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(anyhow!("operation cancelled"))
    }
}

fn prompt_text(prompt: &str) -> Result<String> {
    let value = prompt_line(prompt)?;
    if value.is_empty() {
        return Err(anyhow!("no input provided"));
    }
    Ok(value)
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String> {
    let value = prompt_line(&format!("{prompt} [{default}]: "))?;
    if value.is_empty() {
        return Ok(default.to_owned());
    }
    Ok(value)
}

fn prompt_line(prompt: &str) -> Result<String> {
    let mut stdout = io::stdout().lock();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

fn write_sign_outcome(
    format: OutputFormat,
    outcome: &legacy_ios_kit::AppSignOutcome,
) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(
                &mut output,
                &serde_json::json!({
                    "status": "signed-and-installed-app",
                    "team_id": outcome.team_id,
                    "bundle_id": outcome.bundle_id,
                    "device_registered": outcome.device_registered,
                    "app_id_registered": outcome.app_id_registered,
                }),
            )?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "signed-and-installed-app")?;
            writeln!(output, "Team: {}", outcome.team_id)?;
            writeln!(output, "Bundle ID: {}", outcome.bundle_id)?;
            writeln!(output, "Device registered: {}", outcome.device_registered)?;
            writeln!(output, "App ID registered: {}", outcome.app_id_registered)?;
        }
    }
    Ok(())
}

fn write_message(format: OutputFormat, action: &str, udid: &Udid) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Human => writeln!(output, "Device {action}: {udid}")?,
        OutputFormat::Json => {
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({
                    "action": action,
                    "udid": udid,
                }),
            )?;
            writeln!(output)?;
        }
    }
    Ok(())
}

fn write_diagnostics(format: OutputFormat, diagnostics: &DeviceDiagnostics) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, diagnostics)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            for (key, value) in diagnostics.values() {
                writeln!(output, "{key}: {value:?}")?;
            }
        }
    }
    Ok(())
}

fn write_activation_state(format: OutputFormat, state: &ActivationState) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut output, state)?;
            writeln!(output)?;
        }
        OutputFormat::Human => writeln!(output, "{state:?}")?,
    }
    Ok(())
}

fn write_restore_plan(format: OutputFormat, plan: &RestorePlan) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, plan)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(output, "Plan: {}", plan.id().as_str())?;
            writeln!(
                output,
                "Target: {} ({})",
                plan.product_version(),
                plan.build_id()
            )?;
            writeln!(output, "Firmware: {}", plan.firmware().display())?;
            writeln!(output, "Components: {}", plan.components().len())?;
            for (index, step) in plan.steps().iter().enumerate() {
                writeln!(
                    output,
                    "  {:>2}. {:?} [{:?}]",
                    index + 1,
                    step.kind,
                    step.cancellation
                )?;
            }
        }
    }
    Ok(())
}

fn write_firmware(format: OutputFormat, summary: &FirmwareSummary) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, summary)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(
                output,
                "{} {} ({})",
                summary.product_version(),
                summary.build_id(),
                summary.path().display()
            )?;
            writeln!(
                output,
                "Products: {}",
                summary
                    .supported_product_types()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
            for identity in summary.identities() {
                let behavior = match identity.restore_behavior() {
                    RestoreBehavior::Erase => "erase",
                    RestoreBehavior::Update => "update",
                };
                writeln!(
                    output,
                    "  {}  {}  {} components",
                    identity.board_config(),
                    behavior,
                    identity.component_count()
                )?;
            }
        }
    }
    Ok(())
}

fn write_remote_firmware(format: OutputFormat, summary: &RemoteFirmwareSummary) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, summary)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            writeln!(
                output,
                "{} {} ({} bytes)",
                summary.product_version(),
                summary.build_id(),
                summary.length()
            )?;
            writeln!(output, "URL: {}", summary.url())?;
            writeln!(
                output,
                "Products: {}",
                summary
                    .supported_product_types()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
    }
    Ok(())
}

fn init_tracing(cli: &Cli, config: &AppConfig) -> Result<()> {
    let level = if cli.quiet {
        LevelFilter::WARN
    } else {
        match cli.verbose {
            0 => config.log_level()?,
            1 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .parse("device_reader=off,device_writer=off")
        .context("failed to build tracing filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(io::stderr)
        .try_init()
        .map_err(|error| anyhow!("failed to initialize tracing: {error}"))
}

fn write_inventory(format: OutputFormat, inventory: &DeviceInventory) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, inventory)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            if inventory.devices().is_empty() {
                writeln!(output, "No devices found.")?;
            } else {
                for device in inventory.devices() {
                    write_device(&mut output, device)?;
                }
            }
        }
    }
    Ok(())
}

fn write_host_requirements(format: OutputFormat, diagnostics: &UsbHostDiagnostics) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, diagnostics)?;
            writeln!(output)?;
        }
        OutputFormat::Human => {
            if diagnostics.devices().is_empty() {
                writeln!(output, "No supported Apple USB devices found.")?;
            }
            for device in diagnostics.devices() {
                write!(
                    output,
                    "{}  {:#06x}  {}  {}",
                    device.mode(),
                    device.product_id(),
                    device.access(),
                    device.connection_id()
                )?;
                if let Some(driver) = device.driver() {
                    write!(output, "  driver {driver}")?;
                }
                writeln!(output)?;
            }
            for requirement in diagnostics.requirements() {
                if let Some(connection_id) = requirement.connection_id() {
                    writeln!(
                        output,
                        "Requirement [{}] {}: {}",
                        requirement.code(),
                        connection_id,
                        requirement.message()
                    )?;
                } else {
                    writeln!(
                        output,
                        "Requirement [{}]: {}",
                        requirement.code(),
                        requirement.message()
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn write_device(output: &mut impl Write, device: &DeviceSummary) -> io::Result<()> {
    let product = device
        .product_type()
        .map_or("unknown", |value| value.as_str());
    let name = device.name().unwrap_or("unknown device");
    let version = match (device.product_version(), device.build_version()) {
        (Some(version), Some(build)) => format!("{version} ({build})"),
        _ => "unknown iOS".to_owned(),
    };
    let soc = device
        .soc()
        .map_or_else(|| "unknown SoC".to_owned(), |value| value.to_string());
    let ecid = device
        .ecid()
        .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
    writeln!(
        output,
        "{}  {}  {}  {}  {}  ECID {}  {}",
        device.mode(),
        product,
        name,
        soc,
        version,
        ecid,
        device.connection_id()
    )
}
