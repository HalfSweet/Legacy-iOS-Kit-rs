use idevice::{IdeviceService, services::lockdown::LockdownClient};
use plist::{Dictionary, Value};
use serde::Serialize;
use tracing::debug;

use crate::{NormalDevice, ServiceError, plist_service::PropertyListService};

const MOBILEACTIVATIOND: &str = "com.apple.mobileactivationd";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "value")]
pub enum ActivationState {
    Activated,
    Unactivated,
    Other(String),
}

impl ActivationState {
    fn from_device(value: String) -> Self {
        match value.as_str() {
            "Activated" => Self::Activated,
            "Unactivated" => Self::Unactivated,
            _ => Self::Other(value),
        }
    }
}

impl NormalDevice {
    pub async fn activation_state(&self) -> Result<ActivationState, ServiceError> {
        match activation_command(self, "GetActivationStateRequest").await {
            Ok(response) => {
                let state = response
                    .get("Value")
                    .and_then(Value::as_string)
                    .ok_or(ServiceError::UnexpectedValue("ActivationState"))?;
                Ok(ActivationState::from_device(state.to_owned()))
            }
            Err(error) => {
                debug!(%error, "mobileactivationd state request failed; querying lockdown");
                let mut lockdown = LockdownClient::connect(self.provider()).await?;
                let state = lockdown
                    .get_value(Some("ActivationState"), None)
                    .await?
                    .into_string()
                    .ok_or(ServiceError::UnexpectedValue("ActivationState"))?;
                Ok(ActivationState::from_device(state))
            }
        }
    }

    pub async fn deactivate(&self) -> Result<(), ServiceError> {
        activation_command(self, "DeactivateRequest").await?;
        Ok(())
    }
}

async fn activation_command(
    device: &NormalDevice,
    command: &str,
) -> Result<Dictionary, ServiceError> {
    let stream = device.connect_service(MOBILEACTIVATIOND).await?;
    let mut service = PropertyListService::new(stream);
    let mut request = Dictionary::new();
    request.insert("Command".into(), command.into());
    service.send(&request).await?;
    service.receive().await
}
