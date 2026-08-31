#![forbid(unsafe_code)]

//! Native restored, ASR, FDR, and firmware restore workflows.

mod asr;
mod connector;
mod dispatch;
mod engine;
mod options;
mod plist_framed;
mod restored;

pub use asr::{ASR_PORT, AsrClient, AsrError, AsrProgress};
pub use connector::{
    RestoredConnectError, RestoredConnector, RestoredDataConnector, RestoredSession,
};
pub use dispatch::{DispatchAction, PreparedRestoreData, RestoreDispatchError};
pub use engine::{
    RestoreOutcome, RestoreProgress, RestoreRunError, run_restored, run_restored_session,
    run_restored_session_with_dispatcher, run_restored_with_data_ports,
    run_restored_with_dispatcher,
};
pub use options::RestoreOptions;
pub use plist_framed::{PlistFrameError, PlistFramed};
pub use restored::{
    BasebandStatus, CheckpointMessage, DataRequest, DataType, ProgressMessage, RestoredClient,
    RestoredError, RestoredMessage, RestoredType, StatusMessage,
};
