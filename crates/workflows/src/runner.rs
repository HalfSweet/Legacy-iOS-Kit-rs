use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use legacy_ios_firmware::{FirmwareArchive, FirmwareError};
use legacy_ios_restore::{
    ASR_PORT, AsrClient, AsrProgress, RestoreOptions, RestoreProgress, RestoreRunError,
    RestoredConnectError, RestoredConnector, run_restored_session,
};
use thiserror::Error;

use crate::{
    BasebandPolicy, ExploitPolicy, RestoreBootError, RestorePlan, RestorePreparation, boot_restore,
};

pub async fn run_restore<P>(
    plan: &RestorePlan,
    preparation: &RestorePreparation,
    work_directory: &Path,
    options: &RestoreOptions,
    progress: P,
) -> Result<RestoreExecutionOutcome, RestoreExecutionError>
where
    P: FnMut(RestoreExecutionProgress) + Send,
{
    if plan.id() != preparation.plan_id() {
        return Err(RestoreExecutionError::PreparationMismatch);
    }
    if !matches!(plan.baseband_policy(), BasebandPolicy::None) {
        return Err(RestoreExecutionError::BasebandNotPrepared);
    }
    if matches!(plan.exploit_policy(), ExploitPolicy::Auto) {
        return Err(RestoreExecutionError::ExploitNotResolved);
    }
    let ecid = plan
        .device()
        .ecid()
        .ok_or(RestoreExecutionError::MissingEcid)?;

    let filesystem = work_directory.join(format!("filesystem-{}.dmg", plan.id().as_str()));
    FirmwareArchive::open(plan.firmware())?
        .extract_entry_to(preparation.filesystem_path(), &filesystem)
        .await?;
    boot_restore(preparation, ecid).await?;
    let mut restored = RestoredConnector::default()
        .connect_by_ecid(ecid, Duration::from_secs(60))
        .await?;
    let data_connector = restored.data_connector();
    let progress = Arc::new(Mutex::new(progress));
    let asr_progress = progress.clone();
    let restored_progress = progress.clone();
    let filesystem_for_asr = filesystem.clone();

    run_restored_session(
        &mut restored,
        options,
        preparation.restored_data(),
        move |port| {
            let data_connector = data_connector.clone();
            let filesystem = filesystem_for_asr.clone();
            let progress = asr_progress.clone();
            async move {
                let stream = data_connector.connect(port.unwrap_or(ASR_PORT)).await?;
                let mut asr = AsrClient::initiate(stream).await?;
                asr.validate(&filesystem).await?;
                asr.send_payload(&filesystem, |value| {
                    let mut progress = progress
                        .lock()
                        .expect("restore progress mutex must remain available");
                    progress(RestoreExecutionProgress::Asr(value));
                })
                .await?;
                Ok(())
            }
        },
        move |value| {
            let mut progress = restored_progress
                .lock()
                .expect("restore progress mutex must remain available");
            progress(RestoreExecutionProgress::Restored(value));
        },
    )
    .await?;

    Ok(RestoreExecutionOutcome { filesystem })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreExecutionProgress {
    Asr(AsrProgress),
    Restored(RestoreProgress),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreExecutionOutcome {
    filesystem: PathBuf,
}

impl RestoreExecutionOutcome {
    pub fn filesystem(&self) -> &Path {
        &self.filesystem
    }
}

#[derive(Debug, Error)]
pub enum RestoreExecutionError {
    #[error("restore preparation belongs to another plan")]
    PreparationMismatch,
    #[error("restore execution requires an ECID")]
    MissingEcid,
    #[error("baseband data must be resolved before restore execution")]
    BasebandNotPrepared,
    #[error("automatic exploit policy must be resolved before restore execution")]
    ExploitNotResolved,
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Boot(#[from] RestoreBootError),
    #[error(transparent)]
    Connect(#[from] RestoredConnectError),
    #[error(transparent)]
    Run(#[from] RestoreRunError),
}
