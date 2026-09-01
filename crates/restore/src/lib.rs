#![forbid(unsafe_code)]

//! Native restored, ASR, FDR, and firmware restore workflows.

mod asr;
mod connector;
mod dispatch;
mod engine;
mod fdr;
mod options;
mod plist_framed;
mod restored;

pub use asr::{ASR_PORT, AsrClient, AsrError, AsrProgress};
pub use connector::{
    FdrProxyConnector, FdrProxyFuture, FdrProxyStream, FdrService, FdrServiceError,
    RestoredConnectError, RestoredConnector, RestoredDataConnector, RestoredSession,
    TcpFdrProxyConnector,
};
pub use dispatch::{
    DataResponse, DispatchAction, FILE_DATA_CHUNK_SIZE, PreparedRestoreData, RestoreDispatchError,
    file_data_messages,
};
pub use engine::{
    RestoreOutcome, RestoreProgress, RestoreRunError, run_restored, run_restored_session,
    run_restored_session_with_dispatcher, run_restored_with_data_ports,
    run_restored_with_dispatcher,
};
pub use fdr::{
    FDR_CONTROL_PORT, FdrConnection, FdrConnectionCommand, FdrControl, FdrControlCommand, FdrError,
    FdrProtocol, FdrProxyRequest,
};
pub use options::RestoreOptions;
pub use plist_framed::{PlistFrameError, PlistFramed};
pub use restored::{
    BasebandStatus, BootObjectImage, BootObjectRequest, CheckpointMessage, DataRequest, DataType,
    ProgressMessage, RestoredClient, RestoredError, RestoredMessage, RestoredType, StatusMessage,
};
