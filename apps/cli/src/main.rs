#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use legacy_ios_kit::{
    AppFilter, BasebandPolicy, BoardConfig, DeviceDiagnostics, DeviceInventory, DeviceSummary,
    Ecid, ExploitPolicy, FirmwareSummary, InstalledApp, LegacyIosKit, ProductType,
    RecoveryDeviceInfo, RecoveryUploadResult, RestoreBehavior, RestorePlan, RestoreRequest,
    SepPolicy, TicketPolicy, Udid,
};
use tracing::level_filters::LevelFilter;

#[derive(Debug, Parser)]
#[command(name = "lik", version, about = "Pure-Rust legacy iOS device toolkit")]
struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    output: OutputFormat,
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
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Firmware {
        #[command(subcommand)]
        command: FirmwareCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
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
}

#[derive(Debug, Subcommand)]
enum FirmwareCommand {
    /// Inspect a local IPSW and its BuildManifest.
    Inspect { path: PathBuf },
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli)?;
    let kit = LegacyIosKit::new();

    match cli.command {
        Command::App {
            command: AppCommand::List { udid, filter },
        } => {
            let apps = kit
                .devices()
                .list_apps(&udid, filter.into())
                .await
                .context("failed to list apps")?;
            write_apps(cli.output, &apps)?;
        }
        Command::App {
            command: AppCommand::Install { udid, ipa, yes },
        } => {
            confirm("install the IPA", yes)?;
            kit.devices()
                .install_ipa(&udid, &ipa)
                .await
                .context("failed to install IPA")?;
            write_message(cli.output, "installed-ipa", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::List,
        } => {
            let inventory = kit
                .devices()
                .list()
                .await
                .context("failed to list devices")?;
            write_inventory(cli.output, &inventory)?;
        }
        Command::Device {
            command: DeviceCommand::Pair { udid },
        } => {
            kit.devices()
                .pair(&udid)
                .await
                .context("failed to pair device")?;
            write_message(cli.output, "paired", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::Battery { udid },
        } => {
            let diagnostics = kit
                .devices()
                .battery_info(&udid)
                .await
                .context("failed to read battery diagnostics")?;
            write_diagnostics(cli.output, &diagnostics)?;
        }
        Command::Device {
            command: DeviceCommand::EnterRecovery { udid, yes },
        } => {
            confirm("enter Recovery mode", yes)?;
            kit.devices()
                .enter_recovery(&udid)
                .await
                .context("failed to enter Recovery mode")?;
            write_message(cli.output, "entered-recovery", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::RecoveryInfo { ecid },
        } => {
            let device = kit.recovery().open(ecid).await?;
            write_recovery_info(cli.output, device.mode(), device.info())?;
        }
        Command::Device {
            command: DeviceCommand::Iboot { command, ecid },
        } => {
            kit.recovery()
                .open(ecid)
                .await?
                .send_command(&command)
                .await?;
            write_status(cli.output, "sent-command")?;
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
            write_status(cli.output, status)?;
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
            write_status(cli.output, "uploaded-payload")?;
        }
        Command::Device {
            command: DeviceCommand::ExitRecovery { ecid },
        } => {
            kit.recovery().open(ecid).await?.reboot_to_normal().await?;
            write_status(cli.output, "exited-recovery")?;
        }
        Command::Device {
            command: DeviceCommand::Reset { ecid, yes },
        } => {
            confirm("reset the USB device", yes)?;
            kit.recovery().open(ecid).await?.reset().await?;
            write_status(cli.output, "reset-device")?;
        }
        Command::Device {
            command: DeviceCommand::Restart { udid, yes },
        } => {
            confirm("restart the device", yes)?;
            kit.devices()
                .restart(&udid)
                .await
                .context("failed to restart device")?;
            write_message(cli.output, "restarted", &udid)?;
        }
        Command::Device {
            command: DeviceCommand::Shutdown { udid, yes },
        } => {
            confirm("shut down the device", yes)?;
            kit.devices()
                .shutdown(&udid)
                .await
                .context("failed to shut down device")?;
            write_message(cli.output, "shut-down", &udid)?;
        }
        Command::Firmware {
            command: FirmwareCommand::Inspect { path },
        } => {
            let summary = kit
                .inspect_firmware(path)
                .context("failed to inspect firmware")?;
            write_firmware(cli.output, &summary)?;
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
            write_restore_plan(cli.output, &plan)?;
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

fn init_tracing(cli: &Cli) -> Result<()> {
    let level = if cli.quiet {
        LevelFilter::WARN
    } else {
        match cli.verbose {
            0 => LevelFilter::INFO,
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
