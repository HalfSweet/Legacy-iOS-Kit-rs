//! Read-only device properties and positive jailbreak evidence. AFC2 is
//! optional: jailbreak-installed Cydia can be registered only in SpringBoard.

use idevice::{Idevice, services::afc::AfcClient};
use plist::{Dictionary, Value};
use serde::Serialize;
use std::{fmt, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::{
    DeviceFiles, DeviceSession, DeviceStorageInfo, NormalDevice, NormalDeviceInfo, ServiceError,
    plist_service::PropertyListService,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JailbreakEvidence {
    RootAfc,
    CydiaAndSsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum JailbreakStatus {
    Detected { evidence: JailbreakEvidence },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionIssue {
    SerialNumberUnavailable,
    BatteryUnavailable,
    StorageUnavailable,
    JailbreakProbeUnavailable,
    SshProbeUnavailable,
}

/// A successfully paired device inspection. A missing optional value means
/// unconfirmed, never zero capacity, zero battery, or proof of no jailbreak.
#[derive(Clone, Serialize)]
pub struct DeviceInspection {
    info: NormalDeviceInfo,
    serial_number: Option<String>,
    battery_percent: Option<u8>,
    storage: Option<DeviceStorageInfo>,
    jailbreak: JailbreakStatus,
    ssh_available: Option<bool>,
    issues: Vec<InspectionIssue>,
}

impl DeviceInspection {
    pub fn info(&self) -> &NormalDeviceInfo {
        &self.info
    }
    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }
    pub const fn battery_percent(&self) -> Option<u8> {
        self.battery_percent
    }
    pub fn storage(&self) -> Option<&DeviceStorageInfo> {
        self.storage.as_ref()
    }
    pub const fn jailbreak(&self) -> JailbreakStatus {
        self.jailbreak
    }
    pub const fn ssh_available(&self) -> Option<bool> {
        self.ssh_available
    }
    pub fn issues(&self) -> &[InspectionIssue] {
        &self.issues
    }
}

impl fmt::Debug for DeviceInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceInspection")
            .field("product_type", self.info.product_type())
            .field("jailbreak", &self.jailbreak)
            .field("ssh_available", &self.ssh_available)
            .field("issues", &self.issues)
            .finish_non_exhaustive()
    }
}

impl NormalDevice {
    /// Inspect an already-paired normal-mode device without pairing, launching
    /// apps, changing mode, or authenticating to an SSH account.
    pub async fn inspect(&self) -> Result<DeviceInspection, ServiceError> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut session = self.session().await?;
            let result = inspect_session(self, &mut session).await;
            if result.is_ok() {
                let _ = session.close().await;
            }
            result
        })
        .await
        .map_err(|_| ServiceError::SessionTimeout)?
    }
}

async fn inspect_session(
    device: &NormalDevice,
    session: &mut DeviceSession,
) -> Result<DeviceInspection, ServiceError> {
    let mut values = Dictionary::new();
    for key in [
        "ProductType",
        "HardwareModel",
        "ProductVersion",
        "BuildVersion",
        "UniqueChipID",
        "DeviceName",
    ] {
        values.insert(key.into(), session.get_value(Some(key), None).await?);
    }
    let info = NormalDeviceInfo::from_values(device.udid().clone(), &values)?;
    let mut issues = vec![];
    let serial_number = optional_field(session.get_value(Some("SerialNumber"), None).await)?
        .and_then(Value::into_string)
        .filter(|serial| !serial.is_empty());
    if serial_number.is_none() {
        issues.push(InspectionIssue::SerialNumberUnavailable);
    }
    let battery_percent = optional_field(
        session
            .get_value(
                Some("BatteryCurrentCapacity"),
                Some("com.apple.mobile.battery"),
            )
            .await,
    )?
    .and_then(|value| value.as_unsigned_integer())
    .and_then(|value| u8::try_from(value).ok())
    .filter(|percent| *percent <= 100);
    if battery_percent.is_none() {
        issues.push(InspectionIssue::BatteryUnavailable);
    }
    let storage = read_storage(device, session).await?;
    if storage.is_none() {
        issues.push(InspectionIssue::StorageUnavailable);
    }
    let root_afc = root_access(device, session).await?;
    let cydia = if root_afc {
        false
    } else {
        match cydia_registration(device, session).await? {
            Some(value) => value,
            None => {
                issues.push(InspectionIssue::JailbreakProbeUnavailable);
                false
            }
        }
    };
    let ssh_available = match tokio::time::timeout(PROBE_TIMEOUT, ssh_responding(device)).await {
        Ok(Ok(true)) => Some(true),
        _ => {
            issues.push(InspectionIssue::SshProbeUnavailable);
            None
        }
    };
    Ok(DeviceInspection {
        info,
        serial_number,
        battery_percent,
        storage,
        jailbreak: evidence(root_afc, cydia, ssh_available),
        ssh_available,
        issues,
    })
}

fn evidence(root_afc: bool, cydia: bool, ssh: Option<bool>) -> JailbreakStatus {
    if root_afc {
        JailbreakStatus::Detected {
            evidence: JailbreakEvidence::RootAfc,
        }
    } else if cydia && ssh == Some(true) {
        JailbreakStatus::Detected {
            evidence: JailbreakEvidence::CydiaAndSsh,
        }
    } else {
        JailbreakStatus::Unknown
    }
}

// Logical request rejection consumes a complete response and leaves the
// session usable. Transport/framing errors must abort it, never be swallowed.
fn optional_field<T>(result: Result<T, ServiceError>) -> Result<Option<T>, ServiceError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(
            ServiceError::LockdownRejected { .. } | ServiceError::UnexpectedValue("Value" | "Port"),
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn read_storage(
    device: &NormalDevice,
    session: &mut DeviceSession,
) -> Result<Option<DeviceStorageInfo>, ServiceError> {
    let Some(connection) = optional_field(session.service(device, "com.apple.afc").await)? else {
        return Ok(None);
    };
    let mut files = DeviceFiles::new(AfcClient::new(Idevice::new(
        Box::new(connection),
        "legacy-ios-kit",
    )));
    Ok(tokio::time::timeout(PROBE_TIMEOUT, files.storage_info())
        .await
        .ok()
        .and_then(Result::ok))
}

async fn root_access(
    device: &NormalDevice,
    session: &mut DeviceSession,
) -> Result<bool, ServiceError> {
    let Some(connection) = optional_field(session.service(device, "com.apple.afc2").await)? else {
        return Ok(false);
    };
    let mut afc = AfcClient::new(Idevice::new(Box::new(connection), "legacy-ios-kit"));
    Ok(matches!(
        tokio::time::timeout(PROBE_TIMEOUT, afc.get_file_info("/")).await,
        Ok(Ok(_))
    ))
}

async fn cydia_registration(
    device: &NormalDevice,
    session: &mut DeviceSession,
) -> Result<Option<bool>, ServiceError> {
    let Some(connection) = optional_field(
        session
            .service(device, "com.apple.springboardservices")
            .await,
    )?
    else {
        return Ok(None);
    };
    let read = async {
        let mut springboard = PropertyListService::new(connection);
        springboard
            .send(&Dictionary::from_iter([(
                "command",
                Value::String("getIconState".into()),
            )]))
            .await?;
        let icons = springboard.receive_value().await?;
        if let Some(dict) = icons.as_dictionary() {
            if dict.contains_key("Error") || dict.contains_key("error") {
                return Err(ServiceError::UnexpectedValue("iconState"));
            }
        }
        Ok::<bool, ServiceError>(has_cydia_icon(&icons))
    };
    Ok(tokio::time::timeout(PROBE_TIMEOUT, read)
        .await
        .ok()
        .and_then(Result::ok))
}

fn has_cydia_icon(value: &Value) -> bool {
    match value {
        Value::String(identifier) => identifier == "com.saurik.Cydia",
        Value::Array(icons) => icons.iter().any(has_cydia_icon),
        Value::Dictionary(icon) => {
            ["displayIdentifier", "bundleIdentifier"]
                .iter()
                .any(|key| icon.get(key).and_then(Value::as_string) == Some("com.saurik.Cydia"))
                || icon
                    .values()
                    .filter(|value| matches!(value, Value::Array(_) | Value::Dictionary(_)))
                    .any(has_cydia_icon)
        }
        _ => false,
    }
}

async fn ssh_responding(device: &NormalDevice) -> Result<bool, ServiceError> {
    let mut reader = BufReader::new(device.connect_port(22).await?.take(1024));
    let mut line = String::new();
    for _ in 0..4 {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        if line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_session_reads_are_not_treated_as_missing_optional_values() {
        let interrupted: Result<Value, ServiceError> =
            Err(ServiceError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        assert!(optional_field(interrupted).is_err());
        let denied: Result<Value, ServiceError> = Err(ServiceError::LockdownRejected {
            request: "GetValue",
            code: "GetProhibited".into(),
        });
        assert!(optional_field(denied).unwrap().is_none());
    }
    #[test]
    fn default_jailbreak_does_not_require_afc2() {
        assert_eq!(
            evidence(false, true, Some(true)),
            JailbreakStatus::Detected {
                evidence: JailbreakEvidence::CydiaAndSsh
            }
        );
        assert_eq!(evidence(false, true, None), JailbreakStatus::Unknown);
        assert_eq!(evidence(false, false, Some(true)), JailbreakStatus::Unknown);
        assert_eq!(
            evidence(true, false, None),
            JailbreakStatus::Detected {
                evidence: JailbreakEvidence::RootAfc
            }
        );
    }
    #[test]
    fn cydia_is_found_inside_springboard_folders_but_not_in_folder_names() {
        let folder = Dictionary::from_iter([
            ("displayName", Value::String("Utilities".into())),
            (
                "iconLists",
                Value::Array(vec![Value::Array(vec![Value::Dictionary(
                    Dictionary::from_iter([(
                        "displayIdentifier",
                        Value::String("com.saurik.Cydia".into()),
                    )]),
                )])]),
            ),
        ]);
        assert!(has_cydia_icon(&folder.into()));
        assert!(!has_cydia_icon(
            &Dictionary::from_iter([("displayName", Value::String("com.saurik.Cydia".into()))])
                .into()
        ));
    }
}
