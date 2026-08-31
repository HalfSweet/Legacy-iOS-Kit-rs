use std::path::PathBuf;

use legacy_ios_core::{
    CancellationSafety, DeviceSelector, OperationEvent, OperationId, OperationKind,
    OperationOutcome, OperationPhase, Udid,
};
use serde::{Deserialize, Serialize};

use crate::{
    DeviceManager, KitError, OperationHandle, lease::DeviceLeaseRegistry,
    operation::OperationEmitter,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErasePlan {
    id: OperationId,
    udid: Udid,
}

impl ErasePlan {
    pub(crate) fn new(udid: Udid) -> Self {
        Self {
            id: OperationId::new(uuid::Uuid::new_v4().as_u128()),
            udid,
        }
    }

    pub const fn id(&self) -> OperationId {
        self.id
    }

    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    pub fn confirm_destructive(&self) -> EraseConsent {
        EraseConsent { plan: self.id }
    }
}

pub struct EraseConsent {
    plan: OperationId,
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    plan: ErasePlan,
    consent: EraseConsent,
    work_directory: PathBuf,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(32);
    tokio::spawn(async move {
        if let Err(error) =
            execute(&devices, &leases, &emitter, plan, consent, work_directory).await
        {
            emitter.fail(error).await;
        }
    });
    handle
}

async fn execute(
    devices: &DeviceManager,
    leases: &DeviceLeaseRegistry,
    emitter: &OperationEmitter,
    plan: ErasePlan,
    consent: EraseConsent,
    work_directory: PathBuf,
) -> Result<(), KitError> {
    if consent.plan != plan.id {
        return Err(KitError::EraseConsentMismatch);
    }
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Preflight,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    let _lease = leases
        .acquire(DeviceSelector::Udid(plan.udid.clone()))
        .await;
    if emitter.is_cancelled() {
        return Ok(());
    }
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::TransferringFilesystem,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    let outcome = devices.erase_internal(&plan.udid, &work_directory).await?;
    if emitter.is_cancelled() {
        emitter
            .emit(OperationEvent::CancellationDeferred {
                phase: OperationPhase::TransferringFilesystem,
            })
            .await;
    }
    emitter
        .emit(OperationEvent::Completed {
            outcome: OperationOutcome {
                operation: OperationKind::DataManagement,
                summary: format!(
                    "device erase completed after transferring {} protocol files",
                    outcome.files()
                ),
            },
        })
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_is_bound_to_one_plan() {
        let first = ErasePlan::new(Udid::from("first"));
        let second = ErasePlan::new(Udid::from("second"));
        assert_eq!(first.confirm_destructive().plan, first.id());
        assert_ne!(first.id(), second.id());
    }
}
