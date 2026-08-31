#![forbid(unsafe_code)]

//! High-level Legacy iOS Kit operations.

mod baseband;
mod execution;
mod personalization;
mod restore;

pub use baseband::{BasebandError, BasebandFirmware};
pub use execution::{PreparedBootComponent, RestorePreparation, RestorePreparationError};
pub use personalization::{ComponentPersonalizer, PersonalizationError};
pub use restore::{
    BasebandPolicy, DestructiveConsent, ExploitPolicy, PlanId, RestoreComponent, RestorePlan,
    RestorePlanError, RestoreRequest, RestoreStep, RestoreStepKind, SepPolicy, TicketPolicy,
};
