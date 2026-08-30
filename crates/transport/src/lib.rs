#![forbid(unsafe_code)]

//! Cross-platform USB and multiplexed device transports.

mod locator;

pub use locator::{
    APPLE_VENDOR_ID, DeviceLocator, DeviceWatch, NusbDeviceLocator, ObservedUsbDevice,
    TransportError, UsbDeviceEvent, UsbDeviceId, classify_apple_mode,
};
