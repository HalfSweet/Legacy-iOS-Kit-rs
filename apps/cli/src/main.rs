#![forbid(unsafe_code)]

mod config;

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use legacy_ios_kit::{
    ActivationState, AfcPath, AppFilter, BackupOptions, BackupOutcome, BackupRestoreOptions,
    BasebandPolicy, BoardConfig, DeviceDiagnostics, DeviceFileInfo, DeviceInventory,
    DeviceStorageInfo, DeviceSummary, Ecid, ExploitPolicy, FirmwareSummary, HostKeyPolicy,
    InstalledApp, LegacyIosKit, OperationEvent, OperationHandle, OperationOutcome, ProductType,
    RamdiskSsh, RecoveryDeviceInfo, RecoveryUploadResult, RemoteFirmwareSummary, RestoreBehavior,
    RestoreExecutionRequest, RestorePlan, RestoreRequest, ScpPath, SepPolicy, ShshRequest,
    ShshSummary, SigningTicket, SshCommandOutput, SshPassword, SshTarget, TicketPolicy, Udid,
};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};

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
    /// Uninstall an application by bundle identifier.
    Uninstall {
        udid: Udid,
        bundle_id: String,
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
    /// Pair a normal-mode device and persist its pairing record in the system mux.
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
        #[arg(long, conflicts_with = "no_baseband")]
        baseband: Option<PathBuf>,
        #[arg(long)]
        no_baseband: bool,
        #[arg(long)]
        sep: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ExploitArg::Auto)]
        exploit: ExploitArg,
    },
    /// Execute a previously modeled restore using a provided ticket.
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
        #[arg(long)]
        flash_version_1: bool,
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
    let kit = match config.network.tss_endpoint.as_deref() {
        Some(endpoint) => LegacyIosKit::new()
            .with_tss_endpoint(endpoint)
            .context("invalid configured TSS endpoint")?,
        None => LegacyIosKit::new(),
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
        Command::Config {
            command: ConfigCommand::Show,
        } => write_config(output, &config)?,
        Command::Config {
            command: ConfigCommand::Path,
        } => write_config_path(output, &config.path)?,
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
                    yes,
                },
        } => {
            confirm("restore the device backup", yes)?;
            let options = BackupRestoreOptions::default()
                .reboot(!no_reboot)
                .preserve_settings(!replace_settings)
                .system_files(system_files)
                .remove_items_not_restored(remove_missing);
            let outcome = kit
                .devices()
                .restore_backup(&udid, &root, &source_identifier, options)
                .await
                .context("device backup restore failed")?;
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
                    baseband,
                    no_baseband,
                    sep,
                    exploit,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let ticket = if onboard_ticket {
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
            let sep = sep.map_or(SepPolicy::Auto, SepPolicy::Provided);
            let plan = kit
                .plan_restore(RestoreRequest {
                    device,
                    firmware,
                    behavior: behavior.into(),
                    ticket,
                    baseband,
                    sep,
                    exploit: exploit.into(),
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
                    work_dir,
                    behavior,
                    exploit,
                    limera1n_payload,
                    baseband,
                    no_baseband,
                    sep,
                    flash_version_1,
                    yes,
                },
        } => {
            let device = kit.resolve_device_identity(device, board)?.with_ecid(ecid);
            let plan = kit.plan_restore(RestoreRequest {
                device,
                firmware,
                behavior: behavior.into(),
                ticket: ticket
                    .clone()
                    .map_or(TicketPolicy::Signed, TicketPolicy::Provided),
                baseband: if no_baseband {
                    BasebandPolicy::None
                } else if let Some(baseband) = baseband {
                    BasebandPolicy::Provided(baseband)
                } else {
                    BasebandPolicy::Auto
                },
                sep: sep.map_or(SepPolicy::Auto, SepPolicy::Provided),
                exploit: exploit.into(),
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
            let mut request = if let Some(ticket) = ticket {
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

fn write_config_path(format: OutputFormat, path: &std::path::Path) -> Result<()> {
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
    tracing_subscriber::fmt()
        .with_max_level(level)
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
