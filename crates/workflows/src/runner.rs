use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use legacy_ios_firmware::{FirmwareArchive, FirmwareError, TssClient};
use legacy_ios_restore::{
    ASR_PORT, AsrClient, AsrProgress, DataRequest, DataType, DispatchAction, RestoreOptions,
    RestoreProgress, RestoreRunError, RestoredConnectError, RestoredConnector,
    TcpFdrProxyConnector, run_restored_session_with_dispatcher,
};
use thiserror::Error;
use tracing::warn;

use crate::{
    BasebandPolicy, BasebandRequestError, BasebandResolver, CryptexRequestError, CryptexResolver,
    RestoreBootError, RestorePlan, RestorePreparation, boot_restore, is_cryptex_updater,
};

pub async fn run_restore<P>(
    plan: &RestorePlan,
    preparation: &RestorePreparation,
    tss: &TssClient,
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
    let baseband = match plan.baseband_policy() {
        BasebandPolicy::Auto => Some(Arc::new(BasebandResolver::new(plan, tss.clone())?)),
        BasebandPolicy::None => None,
        BasebandPolicy::Provided(path) => Some(Arc::new(BasebandResolver::from_firmware(
            plan,
            path,
            tss.clone(),
        )?)),
    };
    let cryptex = plan
        .cryptex_source()
        .map(|_| CryptexResolver::new(plan, preparation.ticket_dictionary().clone(), tss.clone()))
        .transpose()?
        .map(Arc::new);
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
    let fdr_task = match data_connector
        .connect_fdr(Arc::new(TcpFdrProxyConnector))
        .await
    {
        Ok(service) => Some(tokio::spawn(async move {
            if let Err(error) = service.run().await {
                warn!(%error, "FDR service stopped");
            }
        })),
        Err(error) => {
            warn!(%error, "FDR service is unavailable");
            None
        }
    };
    let progress = Arc::new(Mutex::new(progress));
    let asr_progress = progress.clone();
    let restored_progress = progress.clone();
    let filesystem_for_asr = filesystem.clone();
    let prepared_data = Arc::new(preparation.restored_data().clone());

    let result = run_restored_session_with_dispatcher(
        &mut restored,
        options,
        move |request: DataRequest| {
            let baseband = baseband.clone();
            let cryptex = cryptex.clone();
            let prepared_data = prepared_data.clone();
            async move {
                match request.data_type() {
                    DataType::Baseband => {
                        let resolver = baseband.ok_or_else(|| {
                            RestoreRunError::data_provider(BasebandRequestError::Disabled)
                        })?;
                        let response = resolver
                            .resolve(&request)
                            .await
                            .map_err(RestoreRunError::data_provider)?;
                        Ok(DispatchAction::Send(response))
                    }
                    DataType::SourceBootObjectV4 | DataType::PersonalizedBootObjectV3 => {
                        let resolver = cryptex.ok_or_else(|| {
                            RestoreRunError::data_provider(CryptexRequestError::Disabled)
                        })?;
                        let data = resolver
                            .boot_object(&request)
                            .await
                            .map_err(RestoreRunError::data_provider)?;
                        Ok(DispatchAction::FileData(data))
                    }
                    DataType::FirmwareUpdater if is_cryptex_updater(&request) => {
                        let resolver = cryptex.ok_or_else(|| {
                            RestoreRunError::data_provider(CryptexRequestError::Disabled)
                        })?;
                        let response = resolver
                            .firmware_updater(&request)
                            .await
                            .map_err(RestoreRunError::data_provider)?;
                        Ok(DispatchAction::Send(response))
                    }
                    _ => Ok(prepared_data.dispatch(&request)?),
                }
            }
        },
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
    .await;
    if let Some(task) = fdr_task {
        task.abort();
    }
    result?;

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
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Baseband(#[from] BasebandRequestError),
    #[error(transparent)]
    Cryptex(#[from] CryptexRequestError),
    #[error(transparent)]
    Boot(#[from] RestoreBootError),
    #[error(transparent)]
    Connect(#[from] RestoredConnectError),
    #[error(transparent)]
    Run(#[from] RestoreRunError),
}
