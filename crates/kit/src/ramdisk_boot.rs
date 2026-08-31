use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use legacy_ios_core::{
    CancellationSafety, OperationEvent, OperationKind, OperationOutcome, OperationPhase, Progress,
    ProgressUnit,
};
use legacy_ios_workflows::{
    DestructiveConsent, RamdiskBootPlan, RamdiskBootPreparation, RamdiskBootProgress, boot_ramdisk,
};

use crate::{
    KitError, OperationHandle, exploit::ensure_pwned, lease::DeviceLeaseRegistry,
    operation::OperationEmitter,
};

pub struct RamdiskBootExecutionRequest {
    plan: RamdiskBootPlan,
    consent: DestructiveConsent,
    limera1n_payload: Option<Vec<u8>>,
}

impl RamdiskBootExecutionRequest {
    pub fn new(plan: RamdiskBootPlan, consent: DestructiveConsent) -> Self {
        Self {
            plan,
            consent,
            limera1n_payload: None,
        }
    }

    pub fn with_limera1n_payload(mut self, payload: Vec<u8>) -> Self {
        self.limera1n_payload = Some(payload);
        self
    }
}

pub(crate) fn spawn(
    leases: DeviceLeaseRegistry,
    request: RamdiskBootExecutionRequest,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(128);
    tokio::spawn(async move {
        match execute(&leases, &emitter, request).await {
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
    leases: &DeviceLeaseRegistry,
    emitter: &OperationEmitter,
    request: RamdiskBootExecutionRequest,
) -> Result<Option<OperationOutcome>, KitError> {
    let plan = request.plan;
    let consent = request.consent;
    let limera1n_payload = request.limera1n_payload;

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
            OperationPhase::Preflight,
            CancellationSafety::Immediate,
        ))
        .await;
    let plan_for_preparation = plan.clone();
    let preparation = tokio::task::spawn_blocking(move || {
        RamdiskBootPreparation::new(&plan_for_preparation, &consent)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }

    if !ensure_pwned(
        plan.device(),
        plan.exploit_policy(),
        limera1n_payload,
        emitter,
    )
    .await?
    {
        drop(lease);
        return Ok(None);
    }

    emitter
        .emit(phase(
            OperationPhase::Booting,
            CancellationSafety::AtCheckpoint,
        ))
        .await;
    let sent = AtomicU64::new(0);
    let deferred = AtomicBool::new(false);
    let callback_emitter = emitter.clone();
    let sent_components = &sent;
    let cancellation_deferred = &deferred;
    boot_ramdisk(&preparation, plan.ecid(), &mut move |progress| {
        if callback_emitter.is_cancelled() && !cancellation_deferred.swap(true, Ordering::Relaxed) {
            callback_emitter.try_emit(OperationEvent::CancellationDeferred {
                phase: OperationPhase::Booting,
            });
        }
        match progress {
            RamdiskBootProgress::SendingComponent { name, bytes } => {
                callback_emitter.try_emit(OperationEvent::Progress(Progress {
                    phase: OperationPhase::Booting,
                    completed: sent_components.fetch_add(1, Ordering::Relaxed) + 1,
                    total: None,
                    unit: ProgressUnit::Steps,
                }));
                callback_emitter.try_emit(OperationEvent::Progress(Progress {
                    phase: OperationPhase::Booting,
                    completed: bytes,
                    total: Some(bytes),
                    unit: ProgressUnit::Bytes,
                }));
                tracing::debug!(component = name, bytes, "sending ramdisk boot component");
            }
            RamdiskBootProgress::WaitingForReconnect => {
                callback_emitter.try_emit(OperationEvent::DeviceDisconnected);
            }
            RamdiskBootProgress::Reconnected { mode } => {
                callback_emitter.try_emit(OperationEvent::ModeChanged { mode });
            }
        }
    })
    .await?;

    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }
    drop(lease);
    Ok(Some(OperationOutcome {
        operation: OperationKind::BootRamdisk,
        summary: format!(
            "ramdisk boot chain completed for {}; connect with `lik ramdisk ssh`",
            plan.device().product_type()
        ),
    }))
}

const fn phase(phase: OperationPhase, cancellation: CancellationSafety) -> OperationEvent {
    OperationEvent::PhaseStarted {
        phase,
        cancellation,
    }
}
