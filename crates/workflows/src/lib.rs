#![forbid(unsafe_code)]

//! High-level Legacy iOS Kit operations.

mod baseband;
mod boot;
mod cryptex;
mod execution;
mod personalization;
mod ramdisk;
mod ramdisk_boot;
mod restore;
mod runner;

pub use baseband::{BasebandError, BasebandFirmware, BasebandRequestError, BasebandResolver};
pub use boot::{RestoreBootError, RestoreBootOutcome, boot_restore};
pub use cryptex::{
    CryptexRequestError, CryptexResolver, is_cryptex_component, is_cryptex_updater,
    rewrite_build_identity,
};
pub use execution::{PreparedBootComponent, RestorePreparation, RestorePreparationError};
pub use personalization::{ComponentPersonalizer, PersonalizationError};
pub use ramdisk::{
    APTICKET, DEFAULT_BOOT_ARGS, DEVICE_TREE, IBEC, IBSS, KERNEL, RAMDISK, RamdiskBootComponent,
    RamdiskBootPlan, RamdiskBootPlanError, RamdiskBootPlanStep, RamdiskBootRequest,
    RamdiskBootStepKind, TRUST_CACHE,
};
pub use ramdisk_boot::{
    RamdiskBootError, RamdiskBootOutcome, RamdiskBootPreparation, RamdiskBootProgress,
    RamdiskPreparationError, boot_ramdisk,
};
pub use restore::{
    BasebandPolicy, BootComponentOverrides, CryptexPolicy, CryptexSource, DestructiveConsent,
    ExploitPolicy, NoncePolicy, PlanId, RestoreComponent, RestorePlan, RestorePlanError,
    RestoreRequest, RestoreStep, RestoreStepKind, RsepPolicy, SepPolicy, TicketPolicy,
};
pub use runner::{
    RestoreExecutionError, RestoreExecutionOutcome, RestoreExecutionProgress, run_restore,
};
