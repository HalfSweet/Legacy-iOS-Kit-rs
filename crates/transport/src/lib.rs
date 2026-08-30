#![forbid(unsafe_code)]

//! Cross-platform USB and multiplexed device transports.

mod iboot;
mod locator;
mod recovery;

pub use iboot::{IbootClient, RecoveryError};
pub use locator::{
    APPLE_VENDOR_ID, DeviceLocator, DeviceWatch, NusbDeviceLocator, ObservedUsbDevice,
    TransportError, UsbDeviceEvent, UsbDeviceId, classify_apple_mode,
};
pub use recovery::{RecoveryDeviceInfo, parse_iboot_serial};
