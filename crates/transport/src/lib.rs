#![forbid(unsafe_code)]

//! Cross-platform USB and multiplexed device transports.

mod host;
mod iboot;
mod locator;
mod platform;
mod recovery;

pub use host::{
    HostRequirement, HostRequirementCode, UsbAccess, UsbHostDevice, UsbHostDiagnostics,
    diagnose_usb_host,
};
pub use iboot::{IbootClient, RecoveryError, UploadResult};
pub use locator::{
    APPLE_VENDOR_ID, DeviceLocator, DeviceWatch, NusbDeviceLocator, ObservedUsbDevice,
    TransportError, UsbDeviceEvent, UsbDeviceId, classify_apple_mode,
};
pub use recovery::{RecoveryDeviceInfo, parse_iboot_serial};
