#![forbid(unsafe_code)]

//! Domain types shared by the Legacy iOS Kit workspace.

mod device;
mod error;
mod operation;

pub use device::{
    BoardConfig, BuildId, Capability, CapabilitySet, ConnectionId, DeviceIdentity, DeviceMode,
    DeviceSelector, DeviceSnapshot, Ecid, IosVersion, ProductType, Soc, Udid,
};
pub use error::{CoreError, Recoverability};
pub use operation::{
    ActionId, ActionKind, CancellationSafety, OperationEvent, OperationId, OperationKind,
    OperationOutcome, OperationPhase, Progress, ProgressUnit,
};
