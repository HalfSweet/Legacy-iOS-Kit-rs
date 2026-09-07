use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::AppFailure;
use crate::ServiceError;

const PENDING: u8 = 0;
const ACTIVE: u8 = 1;
const CANCELLED: u8 = 2;
const COMMITTED: u8 = 3;
const FINISHED: u8 = 4;
const FINISHED_COMMITTED: u8 = 5;

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum AppCancelError {
    #[error("the device request has already been committed")]
    NotCancellable,
    #[error("the application operation has finished")]
    Finished,
}
#[derive(Default)]
pub struct AppOperationControl {
    state: AtomicU8,
    changed: Notify,
}
impl AppOperationControl {
    pub fn cancel(&self) -> Result<(), AppCancelError> {
        match self
            .state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| {
                matches!(state, PENDING | ACTIVE).then_some(CANCELLED)
            }) {
            Ok(_) => {
                self.changed.notify_one();
                Ok(())
            }
            Err(CANCELLED) => Ok(()),
            Err(COMMITTED) => Err(AppCancelError::NotCancellable),
            Err(_) => Err(AppCancelError::Finished),
        }
    }
    pub fn has_committed(&self) -> bool {
        matches!(
            self.state.load(Ordering::SeqCst),
            COMMITTED | FINISHED_COMMITTED
        )
    }
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::SeqCst) == CANCELLED
    }
    pub async fn cancelled(&self) {
        if !self.is_cancelled() {
            self.changed.notified().await;
        }
    }
    pub(super) fn claim(&self) -> Result<OperationGuard<'_>, ServiceError> {
        self.state
            .compare_exchange(PENDING, ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|state| {
                if state == CANCELLED {
                    AppFailure::Cancelled
                } else {
                    AppFailure::ControlUsed
                }
            })?;
        Ok(OperationGuard(self))
    }
    pub(super) fn commit(&self) -> Result<(), ServiceError> {
        self.state
            .compare_exchange(ACTIVE, COMMITTED, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|state| {
                if state == CANCELLED {
                    AppFailure::Cancelled
                } else {
                    AppFailure::ControlUsed
                }
            })?;
        Ok(())
    }
}
pub(super) struct OperationGuard<'a>(&'a AppOperationControl);
impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        let _ =
            self.0
                .state
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| match state {
                    ACTIVE => Some(FINISHED),
                    COMMITTED => Some(FINISHED_COMMITTED),
                    _ => None,
                });
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AppInstallMode {
    Install,
    Upgrade,
}
impl AppInstallMode {
    pub(super) const fn command(self) -> &'static str {
        match self {
            Self::Install => "Install",
            Self::Upgrade => "Upgrade",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AppOperationTimeouts {
    pub service: Duration,
    pub transfer_idle: Duration,
    pub operation: Duration,
    pub cleanup: Duration,
}
impl Default for AppOperationTimeouts {
    fn default() -> Self {
        Self {
            service: Duration::from_secs(30),
            transfer_idle: Duration::from_secs(30),
            operation: Duration::from_secs(180),
            cleanup: Duration::from_secs(5),
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AppProgress {
    Staging { path: String },
    Transfer { bytes: u64, total: u64 },
    Committing,
    Device { percent: Option<u8> },
    Cleanup { complete: bool },
}
/// Only `before_commit` can veto a device request. A consumer can persist its
/// intent there; ordinary progress delivery never interrupts a committed request.
pub trait AppOperationObserver: Send + Sync {
    fn progress(&self, event: AppProgress);
    fn before_commit(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}
impl<F: Fn(AppProgress) + Send + Sync> AppOperationObserver for F {
    fn progress(&self, event: AppProgress) {
        self(event);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppInstallOutcome {
    pub staging_cleanup_complete: bool,
    pub staging_path: String,
}
