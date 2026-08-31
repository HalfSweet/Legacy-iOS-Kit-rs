#![forbid(unsafe_code)]

//! High-level Legacy iOS Kit operations.

mod baseband;
mod boot;
mod execution;
mod personalization;
mod restore;

pub use baseband::{BasebandError, BasebandFirmware};
pub use boot::{RestoreBootError, RestoreBootOutcome, boot_restore};
pub use execution::{PreparedBootComponent, RestorePreparation, RestorePreparationError};
pub use personalization::{ComponentPersonalizer, PersonalizationError};
pub use restore::{
    BasebandPolicy, DestructiveConsent, ExploitPolicy, PlanId, RestoreComponent, RestorePlan,
    RestorePlanError, RestoreRequest, RestoreStep, RestoreStepKind, SepPolicy, TicketPolicy,
};
