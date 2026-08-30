#![forbid(unsafe_code)]

//! Domain types shared by the Legacy iOS Kit workspace.

mod device;
mod error;
mod operation;

pub use device::{
    BoardConfig, Capability, CapabilitySet, ConnectionId, DeviceIdentity, DeviceMode,
    DeviceSelector, DeviceSnapshot, Ecid, ProductType, Soc, Udid,
};
pub use error::{CoreError, Recoverability};
pub use operation::{
    ActionId, ActionKind, CancellationSafety, OperationEvent, OperationId, OperationKind,
    OperationOutcome, OperationPhase, Progress, ProgressUnit,
};
