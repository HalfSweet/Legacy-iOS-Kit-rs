use std::time::Duration;

use legacy_ios_core::{DeviceMode, Ecid};
use nusb::{
    Device, Interface,
    transfer::{ControlOut, ControlType, Recipient, TransferError},
};
use thiserror::Error;
use tracing::{debug, trace};

use crate::{RecoveryDeviceInfo, classify_apple_mode, parse_iboot_serial};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct IbootClient {
    device: Device,
    interface: Interface,
    mode: DeviceMode,
    info: RecoveryDeviceInfo,
}

impl IbootClient {
    pub async fn open(selector: Option<Ecid>) -> Result<Self, RecoveryError> {
        let devices = nusb::list_devices().await?;
        let mut candidates = devices
            .filter_map(|device_info| {
                let mode = classify_apple_mode(device_info.vendor_id(), device_info.product_id())?;
                matches!(
                    mode,
                    DeviceMode::Recovery | DeviceMode::Dfu | DeviceMode::Wtf | DeviceMode::Kis
                )
                .then(|| {
                    let parsed =
                        parse_iboot_serial(device_info.serial_number().unwrap_or_default());
                    (device_info, mode, parsed)
                })
            })
            .filter(|(_, _, info)| selector.is_none_or(|ecid| info.ecid() == Some(ecid)))
            .collect::<Vec<_>>();

        let (device_info, mode, info) = match candidates.len() {
            0 => return Err(RecoveryError::NoDevice),
            1 => candidates.pop().expect("candidate count is one"),
            count => return Err(RecoveryError::AmbiguousDevices(count)),
        };

        debug!(
            product_id = format_args!("{:#06x}", device_info.product_id()),
            ?mode,
            "opening iBoot USB device"
        );
        let device = device_info.open().await?;
        if device.active_configuration().is_err() {
            device.set_configuration(1).await?;
        }
        let interface = device.claim_interface(0).await?;

        Ok(Self {
            device,
            interface,
            mode,
            info,
        })
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub fn device_info(&self) -> &RecoveryDeviceInfo {
        &self.info
    }

    pub async fn send_command(&self, command: &str) -> Result<(), RecoveryError> {
        if self.mode != DeviceMode::Recovery {
            return Err(RecoveryError::CommandRequiresRecovery(self.mode));
        }
        if command.len() >= 0x100 || command.as_bytes().contains(&0) {
            return Err(RecoveryError::InvalidCommand);
        }
        if self.info.effective_cpid() == 0x8900 && self.info.ecid().is_none() {
            return Err(RecoveryError::LegacyCommandProtocol);
        }

        let mut data = Vec::with_capacity(command.len() + 1);
        data.extend_from_slice(command.as_bytes());
        data.push(0);
        let request = command_request(command);
        trace!(request, command, "sending iBoot command");
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value: 0,
                    index: 0,
                    data: &data,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    pub async fn reboot_to_normal(&self) -> Result<(), RecoveryError> {
        self.send_command("setenv auto-boot true").await?;
        self.send_command("saveenv").await?;
        self.send_command("reboot").await
    }

    pub async fn reset(self) -> Result<(), RecoveryError> {
        self.device.reset().await?;
        Ok(())
    }
}

fn command_request(command: &str) -> u8 {
    match command {
        "go" | "bootx" | "reboot" | "memboot" => 1,
        _ => 0,
    }
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("no Apple device was found in Recovery, DFU, WTF, or KIS mode")]
    NoDevice,
    #[error("multiple matching recovery devices were found ({0})")]
    AmbiguousDevices(usize),
    #[error("iBoot commands require Recovery mode, found {0:?}")]
    CommandRequiresRecovery(DeviceMode),
    #[error("iBoot command must be shorter than 256 bytes and contain no NUL")]
    InvalidCommand,
    #[error("the early iOS command protocol is required for this device")]
    LegacyCommandProtocol,
    #[error("USB device access failed: {0}")]
    Usb(#[from] nusb::Error),
    #[error("USB control transfer failed: {0}")]
    Transfer(#[from] TransferError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_commands_use_request_one() {
        assert_eq!(command_request("bootx"), 1);
        assert_eq!(command_request("reboot"), 1);
        assert_eq!(command_request("getenv build-version"), 0);
    }
}
