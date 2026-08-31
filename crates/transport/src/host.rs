use std::fmt;

use legacy_ios_core::{ConnectionId, DeviceMode};
use serde::{Deserialize, Serialize};

use crate::{APPLE_VENDOR_ID, TransportError, classify_apple_mode, platform::ProbePolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsbAccess {
    Available,
    SystemManaged,
    Busy,
    PermissionDenied,
    Unsupported,
    Disconnected,
    Other,
}

impl fmt::Display for UsbAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Available => "available",
            Self::SystemManaged => "system-managed",
            Self::Busy => "busy",
            Self::PermissionDenied => "permission-denied",
            Self::Unsupported => "unsupported",
            Self::Disconnected => "disconnected",
            Self::Other => "unavailable",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostRequirementCode {
    LinuxUsbPermissions,
    WindowsUsbDriver,
    UsbDeviceBusy,
    ReconnectDevice,
    UsbAccessUnavailable,
    FuseDriver,
}

impl fmt::Display for HostRequirementCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::LinuxUsbPermissions => "linux-usb-permissions",
            Self::WindowsUsbDriver => "windows-usb-driver",
            Self::UsbDeviceBusy => "usb-device-busy",
            Self::ReconnectDevice => "reconnect-device",
            Self::UsbAccessUnavailable => "usb-access-unavailable",
            Self::FuseDriver => "fuse-driver",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsbHostDevice {
    connection_id: ConnectionId,
    product_id: u16,
    mode: DeviceMode,
    access: UsbAccess,
    driver: Option<String>,
}

impl UsbHostDevice {
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub const fn product_id(&self) -> u16 {
        self.product_id
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub const fn access(&self) -> UsbAccess {
        self.access
    }

    pub fn driver(&self) -> Option<&str> {
        self.driver.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostRequirement {
    code: HostRequirementCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_id: Option<ConnectionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<DeviceMode>,
    message: String,
}

impl HostRequirement {
    /// Create a host-level requirement that is not tied to a specific device.
    pub fn new(code: HostRequirementCode, message: impl Into<String>) -> Self {
        Self {
            code,
            connection_id: None,
            mode: None,
            message: message.into(),
        }
    }

    fn for_device(
        code: HostRequirementCode,
        connection_id: ConnectionId,
        mode: DeviceMode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            connection_id: Some(connection_id),
            mode: Some(mode),
            message: message.into(),
        }
    }

    pub const fn code(&self) -> HostRequirementCode {
        self.code
    }

    pub fn connection_id(&self) -> Option<&ConnectionId> {
        self.connection_id.as_ref()
    }

    pub const fn mode(&self) -> Option<DeviceMode> {
        self.mode
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsbHostDiagnostics {
    devices: Vec<UsbHostDevice>,
    requirements: Vec<HostRequirement>,
}

impl UsbHostDiagnostics {
    pub fn devices(&self) -> &[UsbHostDevice] {
        &self.devices
    }

    pub fn requirements(&self) -> &[HostRequirement] {
        &self.requirements
    }

    pub fn is_ready(&self) -> bool {
        self.requirements.is_empty()
    }
}

pub async fn diagnose_usb_host() -> Result<UsbHostDiagnostics, TransportError> {
    let infos = nusb::list_devices().await?;
    let mut diagnostics = UsbHostDiagnostics::default();

    for info in infos.filter(|info| info.vendor_id() == APPLE_VENDOR_ID) {
        let Some(mode) = classify_apple_mode(info.vendor_id(), info.product_id()) else {
            continue;
        };
        let connection_id = connection_id(&info);
        let driver = crate::platform::driver_name(&info);
        let access = match crate::platform::probe_policy(mode, &info) {
            ProbePolicy::SystemManaged => UsbAccess::SystemManaged,
            ProbePolicy::Open => match info.open().await {
                Ok(_) => UsbAccess::Available,
                Err(error) => access_from_error(error.kind()),
            },
        };
        diagnostics.devices.push(UsbHostDevice {
            connection_id: connection_id.clone(),
            product_id: info.product_id(),
            mode,
            access,
            driver,
        });
        if let Some(requirement) = requirement(connection_id, mode, access) {
            diagnostics.requirements.push(requirement);
        }
    }

    Ok(diagnostics)
}

fn connection_id(info: &nusb::DeviceInfo) -> ConnectionId {
    if info.port_chain().is_empty() {
        return ConnectionId::new(format!(
            "{}:address-{}",
            info.bus_id(),
            info.device_address()
        ));
    }
    let ports = info
        .port_chain()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".");
    ConnectionId::new(format!("{}:{ports}", info.bus_id()))
}

fn access_from_error(kind: nusb::ErrorKind) -> UsbAccess {
    match kind {
        nusb::ErrorKind::Disconnected | nusb::ErrorKind::NotFound => UsbAccess::Disconnected,
        nusb::ErrorKind::Busy => UsbAccess::Busy,
        nusb::ErrorKind::PermissionDenied => UsbAccess::PermissionDenied,
        nusb::ErrorKind::Unsupported => UsbAccess::Unsupported,
        _ => UsbAccess::Other,
    }
}

fn requirement(
    connection_id: ConnectionId,
    mode: DeviceMode,
    access: UsbAccess,
) -> Option<HostRequirement> {
    let (code, message) = match access {
        UsbAccess::Available | UsbAccess::SystemManaged => return None,
        UsbAccess::PermissionDenied if cfg!(target_os = "linux") => (
            HostRequirementCode::LinuxUsbPermissions,
            "Install a udev rule that grants the current user access to Apple USB devices, then replug the device.",
        ),
        UsbAccess::PermissionDenied | UsbAccess::Unsupported if cfg!(target_os = "windows") => (
            HostRequirementCode::WindowsUsbDriver,
            "Configure a compatible WinUSB driver for direct access to this device mode; retain the Apple driver for Normal mode when using the system backend.",
        ),
        UsbAccess::Busy => (
            HostRequirementCode::UsbDeviceBusy,
            "Close the application currently using this USB device, then retry without changing system USB services.",
        ),
        UsbAccess::Disconnected => (
            HostRequirementCode::ReconnectDevice,
            "Reconnect the device and retry the host diagnostics.",
        ),
        UsbAccess::PermissionDenied | UsbAccess::Unsupported | UsbAccess::Other => (
            HostRequirementCode::UsbAccessUnavailable,
            "Direct USB access is unavailable on this host configuration.",
        ),
    };
    Some(HostRequirement::for_device(
        code,
        connection_id,
        mode,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_and_system_managed_devices_need_no_host_change() {
        for access in [UsbAccess::Available, UsbAccess::SystemManaged] {
            assert!(requirement(ConnectionId::from("1:2"), DeviceMode::Normal, access).is_none());
        }
    }

    #[test]
    fn busy_devices_have_actionable_requirement() {
        let requirement = requirement(
            ConnectionId::from("1:2"),
            DeviceMode::Recovery,
            UsbAccess::Busy,
        )
        .expect("busy device should have a requirement");
        assert_eq!(requirement.code(), HostRequirementCode::UsbDeviceBusy);
    }
}
