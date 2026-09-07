use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AppPhase {
    Service,
    Lookup,
    Transfer,
    Installation,
    Uninstallation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AppRejection {
    Signature,
    Compatibility,
    AlreadyInstalled,
    NotFound,
    Storage,
    Package,
    Other,
}
#[derive(Debug, thiserror::Error)]
pub enum AppFailure {
    #[error("application operation cancelled before submission")]
    Cancelled,
    #[error("application operation control has already been used")]
    ControlUsed,
    #[error("invalid application identifier")]
    InvalidIdentifier,
    #[error("invalid IPA package")]
    InvalidPackage,
    #[error("IPA changed after inspection")]
    DigestMismatch,
    #[error("IPA inspection task failed")]
    InspectionTask,
    #[error("invalid installation proxy response")]
    InvalidResponse,
    #[error("system applications cannot be managed through User installation")]
    SystemApplication,
    #[error("application type could not be confirmed")]
    UnknownApplicationType,
    #[error("application is not installed")]
    NotInstalled,
    #[error("application is already installed; use upgrade")]
    AlreadyInstalled,
    #[error("operation intent could not be recorded")]
    ObserverRejected,
    #[error("application operation timed out during {0:?}")]
    TimedOut(AppPhase),
    #[error("device rejected application operation: {0:?}")]
    Rejected(AppRejection),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppIdentifier(String);
impl AppIdentifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppFailure> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AppFailure::InvalidIdentifier);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for AppIdentifier {
    type Error = AppFailure;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
impl From<AppIdentifier> for String {
    fn from(value: AppIdentifier) -> Self {
        value.0
    }
}
