use std::path::{Path, PathBuf};

use legacy_ios_core::{BoardConfig, BuildId, Ecid, IosVersion};
use legacy_ios_firmware::{ApParameters, FirmwareArchive, RestoreBehavior, TssClient, TssRequest};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::KitError;

#[derive(Clone, Debug)]
pub struct ShshRequest {
    firmware: PathBuf,
    board_config: BoardConfig,
    behavior: RestoreBehavior,
    parameters: ApParameters,
}

impl ShshRequest {
    pub fn new(
        firmware: impl Into<PathBuf>,
        board_config: BoardConfig,
        behavior: RestoreBehavior,
        ecid: Ecid,
        board_id: u64,
        chip_id: u64,
    ) -> Self {
        Self {
            firmware: firmware.into(),
            board_config,
            behavior,
            parameters: ApParameters::new(board_id, chip_id, ecid),
        }
    }

    pub fn with_ap_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.parameters.ap_nonce = Some(nonce);
        self
    }

    pub fn with_sep_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.parameters.sep_nonce = Some(nonce);
        self
    }

    pub fn with_img4_support(mut self, supported: bool) -> Self {
        self.parameters.supports_img4 = supported;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShshSummary {
    path: PathBuf,
    product_version: IosVersion,
    build_id: BuildId,
    board_config: BoardConfig,
}

impl ShshSummary {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn product_version(&self) -> &IosVersion {
        &self.product_version
    }

    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    pub fn board_config(&self) -> &BoardConfig {
        &self.board_config
    }
}

pub(crate) async fn save(
    client: &TssClient,
    request: &ShshRequest,
    destination: &Path,
) -> Result<ShshSummary, KitError> {
    let archive = FirmwareArchive::open(&request.firmware)?;
    let manifest = archive.build_manifest()?;
    let identity = manifest.select_identity(&request.board_config, request.behavior)?;
    let tss_request = TssRequest::for_build_identity(identity, &request.parameters);
    let response = client.send(&tss_request).await?;
    let mut data = Vec::new();
    plist::to_writer_xml(&mut data, response.dictionary())?;
    persist(destination, &data).await?;
    info!(path = %destination.display(), "saved signing ticket");

    Ok(ShshSummary {
        path: destination.to_owned(),
        product_version: manifest.product_version().clone(),
        build_id: manifest.build_id().clone(),
        board_config: request.board_config.clone(),
    })
}

async fn persist(destination: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let temporary = tempfile::Builder::new()
        .prefix("shsh-")
        .tempfile_in(parent)?
        .into_temp_path();
    let mut file = tokio::fs::File::create(&temporary).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    drop(file);
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    Ok(())
}
