use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Recoverability {
    RetryImmediately,
    ReconnectDevice,
    ReenterDfu,
    RestartOperation,
    ManualRecoveryRequired,
    NotRecoverable,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid ECID: {0}")]
    InvalidEcid(String),
}
