use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures_core::Stream;
use futures_util::{StreamExt, future};
use legacy_ios_core::{ConnectionId, DeviceMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

pub const APPLE_VENDOR_ID: u16 = 0x05ac;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UsbDeviceId(String);

impl UsbDeviceId {
    fn from_nusb(id: nusb::DeviceId) -> Self {
        Self(format!("{id:?}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedUsbDevice {
    id: UsbDeviceId,
    connection_id: ConnectionId,
    product_id: u16,
    mode: DeviceMode,
    serial_number: Option<String>,
    product_name: Option<String>,
}

impl ObservedUsbDevice {
    fn from_info(info: &nusb::DeviceInfo, mode: DeviceMode) -> Self {
        Self {
            id: UsbDeviceId::from_nusb(info.id()),
            connection_id: connection_id(info.bus_id(), info.port_chain(), info.device_address()),
            product_id: info.product_id(),
            mode,
            serial_number: info.serial_number().map(ToOwned::to_owned),
            product_name: info.product_string().map(ToOwned::to_owned),
        }
    }

    pub fn id(&self) -> &UsbDeviceId {
        &self.id
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub const fn product_id(&self) -> u16 {
        self.product_id
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    pub fn product_name(&self) -> Option<&str> {
        self.product_name.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsbDeviceEvent {
    Connected(ObservedUsbDevice),
    Disconnected(UsbDeviceId),
}

pub type DeviceWatch = Pin<Box<dyn Stream<Item = UsbDeviceEvent> + Send>>;
pub type DeviceListFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<ObservedUsbDevice>, TransportError>> + Send + 'a>>;

pub trait DeviceLocator: Send + Sync {
    fn list(&self) -> DeviceListFuture<'_>;
    fn watch(&self) -> Result<DeviceWatch, TransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NusbDeviceLocator;

impl DeviceLocator for NusbDeviceLocator {
    fn list(&self) -> DeviceListFuture<'_> {
        Box::pin(async {
            let devices = nusb::list_devices().await?;
            let observed = devices
                .filter_map(|info| {
                    classify_apple_mode(info.vendor_id(), info.product_id())
                        .map(|mode| ObservedUsbDevice::from_info(&info, mode))
                })
                .collect();
            Ok(observed)
        })
    }

    fn watch(&self) -> Result<DeviceWatch, TransportError> {
        let known = Arc::new(Mutex::new(HashSet::new()));
        let stream = nusb::watch_devices()?.filter_map(move |event| {
            let mapped = match event {
                nusb::hotplug::HotplugEvent::Connected(info) => {
                    classify_apple_mode(info.vendor_id(), info.product_id()).map(|mode| {
                        debug!(
                            product_id = format_args!("{:#06x}", info.product_id()),
                            ?mode,
                            "Apple USB device connected"
                        );
                        known
                            .lock()
                            .expect("USB device set mutex must remain available")
                            .insert(info.id());
                        UsbDeviceEvent::Connected(ObservedUsbDevice::from_info(&info, mode))
                    })
                }
                nusb::hotplug::HotplugEvent::Disconnected(id) => known
                    .lock()
                    .expect("USB device set mutex must remain available")
                    .remove(&id)
                    .then(|| UsbDeviceEvent::Disconnected(UsbDeviceId::from_nusb(id))),
            };
            future::ready(mapped)
        });

        Ok(Box::pin(stream))
    }
}

pub const fn classify_apple_mode(vendor_id: u16, product_id: u16) -> Option<DeviceMode> {
    if vendor_id != APPLE_VENDOR_ID {
        return None;
    }

    match product_id {
        0x1222 => Some(DeviceMode::Wtf),
        0x1227 => Some(DeviceMode::Dfu),
        0x1280..=0x1283 => Some(DeviceMode::Recovery),
        0x1881 => Some(DeviceMode::Kis),
        0x1290..=0x12af | 0x1901..=0x1905 => Some(DeviceMode::Normal),
        _ => None,
    }
}

fn connection_id(bus_id: &str, port_chain: &[u8], device_address: u8) -> ConnectionId {
    if port_chain.is_empty() {
        return ConnectionId::new(format!("{bus_id}:address-{device_address}"));
    }

    let ports = port_chain
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".");
    ConnectionId::new(format!("{bus_id}:{ports}"))
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("USB access failed: {0}")]
    Usb(#[from] nusb::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_legacy_apple_usb_modes() {
        assert_eq!(
            classify_apple_mode(APPLE_VENDOR_ID, 0x1222),
            Some(DeviceMode::Wtf)
        );
        assert_eq!(
            classify_apple_mode(APPLE_VENDOR_ID, 0x1227),
            Some(DeviceMode::Dfu)
        );
        assert_eq!(
            classify_apple_mode(APPLE_VENDOR_ID, 0x1283),
            Some(DeviceMode::Recovery)
        );
        assert_eq!(
            classify_apple_mode(APPLE_VENDOR_ID, 0x1881),
            Some(DeviceMode::Kis)
        );
        assert_eq!(
            classify_apple_mode(APPLE_VENDOR_ID, 0x129a),
            Some(DeviceMode::Normal)
        );
        assert_eq!(classify_apple_mode(0xffff, 0x1227), None);
    }

    #[test]
    fn connection_id_prefers_stable_port_path() {
        assert_eq!(connection_id("1", &[2, 3], 9), ConnectionId::from("1:2.3"));
        assert_eq!(
            connection_id("1", &[], 9),
            ConnectionId::from("1:address-9")
        );
    }
}
