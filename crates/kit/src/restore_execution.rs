use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use legacy_ios_core::{
    ActionId, ActionKind, CancellationSafety, OperationEvent, OperationKind, OperationOutcome,
    OperationPhase, Progress, ProgressUnit, Soc,
};
use legacy_ios_exploits::{ExploitError, ExternalA5Pwn, Limera1n};
use legacy_ios_firmware::{ApParameters, FirmwareArchive, SigningTicket, TssClient, TssRequest};
use legacy_ios_restore::RestoreOptions;
use legacy_ios_transport::{IbootClient, RecoveryError};
use legacy_ios_workflows::{
    BasebandPolicy, DestructiveConsent, ExploitPolicy, RestoreExecutionProgress, RestorePlan,
    RestorePreparation, TicketPolicy, run_restore,
};
use tracing::debug;

use crate::{
    DeviceManager, KitError, OperationHandle, lease::DeviceLeaseRegistry,
    operation::OperationEmitter,
};

pub struct RestoreExecutionRequest {
    plan: RestorePlan,
    consent: DestructiveConsent,
    ticket: ExecutionTicket,
    work_directory: PathBuf,
    flash_version_1: bool,
    limera1n_payload: Option<Vec<u8>>,
}

impl RestoreExecutionRequest {
    pub fn new(
        plan: RestorePlan,
        consent: DestructiveConsent,
        ticket: SigningTicket,
        work_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plan,
            consent,
            ticket: ExecutionTicket::Provided(ticket),
            work_directory: work_directory.into(),
            flash_version_1: false,
            limera1n_payload: None,
        }
    }

    pub fn signed(
        plan: RestorePlan,
        consent: DestructiveConsent,
        work_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plan,
            consent,
            ticket: ExecutionTicket::Signed,
            work_directory: work_directory.into(),
            flash_version_1: false,
            limera1n_payload: None,
        }
    }

    pub fn with_flash_version_1(mut self, enabled: bool) -> Self {
        self.flash_version_1 = enabled;
        self
    }

    pub fn with_limera1n_payload(mut self, payload: Vec<u8>) -> Self {
        self.limera1n_payload = Some(payload);
        self
    }
}

enum ExecutionTicket {
    Provided(SigningTicket),
    Signed,
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    tss: TssClient,
    request: RestoreExecutionRequest,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(128);
    tokio::spawn(async move {
        match execute(&devices, &leases, &tss, &emitter, request).await {
            Ok(Some(outcome)) => {
                emitter.emit(OperationEvent::Completed { outcome }).await;
            }
            Ok(None) => {}
            Err(error) => emitter.fail(error).await,
        }
    });
    handle
}

async fn execute(
    devices: &DeviceManager,
    leases: &DeviceLeaseRegistry,
    tss: &TssClient,
    emitter: &OperationEmitter,
    request: RestoreExecutionRequest,
) -> Result<Option<OperationOutcome>, KitError> {
    let plan = request.plan;
    let consent = request.consent;
    let ticket_source = request.ticket;
    let flash_version_1 = request.flash_version_1;
    let limera1n_payload = request.limera1n_payload;
    let work_directory = request.work_directory;

    emitter
        .emit(phase(
            OperationPhase::WaitingForDevice,
            CancellationSafety::Immediate,
        ))
        .await;
    let lease = leases.acquire(plan.selector().clone()).await;
    if emitter.is_cancelled() {
        return Ok(None);
    }

    emitter
        .emit(phase(
            OperationPhase::Personalizing,
            CancellationSafety::AtCheckpoint,
        ))
        .await;
    let ticket = resolve_ticket(&plan, ticket_source, tss).await?;
    let plan_for_preparation = plan.clone();
    let preparation = tokio::task::spawn_blocking(move || {
        RestorePreparation::with_ticket(&plan_for_preparation, &consent, ticket, flash_version_1)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    if emitter.is_cancelled() {
        return Ok(None);
    }

    if !resolve_exploit(&plan, limera1n_payload, emitter).await? {
        drop(lease);
        return Ok(None);
    }

    emitter
        .emit(phase(
            OperationPhase::Booting,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ))
        .await;
    let asr_started = Arc::new(AtomicBool::new(false));
    let restored_started = Arc::new(AtomicBool::new(false));
    let cancellation_deferred = Arc::new(AtomicBool::new(false));
    let callback_emitter = emitter.clone();
    let asr_phase = asr_started.clone();
    let restored_phase = restored_started.clone();
    let deferred = cancellation_deferred.clone();
    let options = match plan.behavior() {
        legacy_ios_firmware::RestoreBehavior::Erase => RestoreOptions::erase(),
        legacy_ios_firmware::RestoreBehavior::Update => RestoreOptions::update(),
    };
    let options = if matches!(plan.baseband_policy(), BasebandPolicy::None) {
        options.without_baseband()
    } else {
        options
    };

    run_restore(
        &plan,
        &preparation,
        tss,
        &work_directory,
        &options,
        move |value| {
            if callback_emitter.is_cancelled() && !deferred.swap(true, Ordering::Relaxed) {
                callback_emitter.try_emit(OperationEvent::CancellationDeferred {
                    phase: OperationPhase::Restoring,
                });
            }
            match value {
                RestoreExecutionProgress::Asr(value) => {
                    if !asr_phase.swap(true, Ordering::Relaxed) {
                        callback_emitter.try_emit(phase(
                            OperationPhase::TransferringFilesystem,
                            CancellationSafety::UnsafeUntilPhaseEnds,
                        ));
                    }
                    callback_emitter.try_emit(OperationEvent::Progress(Progress {
                        phase: OperationPhase::TransferringFilesystem,
                        completed: value.transferred,
                        total: Some(value.total),
                        unit: ProgressUnit::Bytes,
                    }));
                }
                RestoreExecutionProgress::Restored(value) => {
                    if !restored_phase.swap(true, Ordering::Relaxed) {
                        callback_emitter.try_emit(phase(
                            OperationPhase::Restoring,
                            CancellationSafety::UnsafeUntilPhaseEnds,
                        ));
                    }
                    callback_emitter.try_emit(OperationEvent::Progress(Progress {
                        phase: OperationPhase::Restoring,
                        completed: value.completed,
                        total: Some(100),
                        unit: ProgressUnit::Percent,
                    }));
                }
            }
        },
    )
    .await?;

    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }
    emitter
        .emit(phase(
            OperationPhase::Verifying,
            CancellationSafety::Immediate,
        ))
        .await;
    let expected = format!("{} ({})", plan.product_version(), plan.build_id());
    let actual = wait_for_normal_device(devices, &plan, emitter).await?;
    if actual != expected {
        return Err(KitError::VersionMismatch { expected, actual });
    }
    drop(lease);
    Ok(Some(OperationOutcome {
        operation: OperationKind::Restore,
        summary: format!("restored {actual}"),
    }))
}

async fn resolve_ticket(
    plan: &RestorePlan,
    source: ExecutionTicket,
    tss: &TssClient,
) -> Result<SigningTicket, KitError> {
    match source {
        ExecutionTicket::Provided(ticket) => {
            if matches!(plan.ticket_policy(), TicketPolicy::Signed) {
                return Err(KitError::TicketPolicyMismatch);
            }
            Ok(ticket)
        }
        ExecutionTicket::Signed => {
            if !matches!(plan.ticket_policy(), TicketPolicy::Signed) {
                return Err(KitError::TicketPolicyMismatch);
            }
            let ecid = plan
                .device()
                .ecid()
                .ok_or(KitError::MissingDeviceSelector)?;
            let client = IbootClient::open(Some(ecid)).await?;
            let info = client.device_info();
            let chip_id = u64::from(
                info.cpid()
                    .ok_or(KitError::MissingSigningDeviceInfo("CPID"))?,
            );
            let board_id = u64::from(
                info.bdid()
                    .ok_or(KitError::MissingSigningDeviceInfo("BDID"))?,
            );
            let mut parameters = ApParameters::new(board_id, chip_id, ecid);
            parameters.ap_nonce = info.ap_nonce().map(ToOwned::to_owned);
            parameters.sep_nonce = info.sep_nonce().map(ToOwned::to_owned);
            parameters.supports_img4 = matches!(
                plan.device().soc(),
                Soc::A7 | Soc::A8 | Soc::A8x | Soc::A9 | Soc::A9x | Soc::A10 | Soc::A10x | Soc::A11
            );
            parameters.in_rom_dfu = client.mode() == legacy_ios_core::DeviceMode::Dfu;
            drop(client);

            let archive = FirmwareArchive::open(plan.firmware())?;
            let manifest = archive.build_manifest()?;
            let board = plan
                .device()
                .board_config()
                .ok_or(KitError::MissingSigningDeviceInfo("BoardConfig"))?;
            let identity = manifest.select_identity(board, plan.behavior())?;
            let request = TssRequest::for_build_identity(identity, &parameters);
            let response = tss.send(&request).await?;
            Ok(SigningTicket::from_dictionary(response.into_dictionary())?)
        }
    }
}

async fn resolve_exploit(
    plan: &RestorePlan,
    limera1n_payload: Option<Vec<u8>>,
    emitter: &OperationEmitter,
) -> Result<bool, KitError> {
    if plan.exploit_policy() != ExploitPolicy::Auto {
        return Ok(true);
    }
    emitter
        .emit(phase(
            OperationPhase::Exploiting,
            CancellationSafety::AtCheckpoint,
        ))
        .await;
    let ecid = plan
        .device()
        .ecid()
        .ok_or(KitError::MissingDeviceSelector)?;
    match plan.device().soc() {
        Soc::S5l8920 | Soc::S5l8922 | Soc::A4 => {
            let payload = limera1n_payload.ok_or(KitError::MissingLimera1nPayload)?;
            let client = IbootClient::open(Some(ecid)).await?;
            let client = Limera1n::new(payload)?.exploit(client).await?;
            if client.device_info().pwned().is_none() {
                return Err(KitError::PwnVerificationFailed);
            }
            Ok(true)
        }
        soc @ (Soc::A5 | Soc::A5x) => {
            emitter
                .emit(OperationEvent::ActionRequired {
                    id: ActionId::new(1),
                    action: ActionKind::UseExternalPwnHardware {
                        family: "A5/A5X checkm8".into(),
                    },
                })
                .await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
            loop {
                if emitter.is_cancelled() {
                    return Ok(false);
                }
                match IbootClient::open(Some(ecid)).await {
                    Ok(client) => match ExternalA5Pwn::verify(&client, soc) {
                        Ok(_) => return Ok(true),
                        Err(ExploitError::NotPwned) => {}
                        Err(ExploitError::UnsupportedSoc(_)) => {
                            return Err(KitError::AutomaticExploitUnsupported(soc));
                        }
                    },
                    Err(RecoveryError::NoDevice) => {}
                    Err(error) => return Err(error.into()),
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(KitError::ExternalExploitTimeout);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        soc => Err(KitError::AutomaticExploitUnsupported(soc)),
    }
}

async fn wait_for_normal_device(
    devices: &DeviceManager,
    plan: &RestorePlan,
    emitter: &OperationEmitter,
) -> Result<String, KitError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if emitter.is_cancelled() {
            return Err(KitError::VerificationTimeout);
        }
        match devices.list_normal().await {
            Ok(summaries) => {
                if let Some(device) = summaries
                    .into_iter()
                    .find(|device| device.ecid() == plan.device().ecid())
                {
                    if let Some(snapshot) = device.snapshot() {
                        emitter
                            .emit(OperationEvent::DeviceReconnected { device: snapshot })
                            .await;
                    }
                    return Ok(format!(
                        "{} ({})",
                        device.product_version().unwrap_or("unknown"),
                        device.build_version().unwrap_or("unknown")
                    ));
                }
            }
            Err(error) => debug!(%error, "normal device not ready for verification"),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(KitError::VerificationTimeout);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

const fn phase(phase: OperationPhase, cancellation: CancellationSafety) -> OperationEvent {
    OperationEvent::PhaseStarted {
        phase,
        cancellation,
    }
}
