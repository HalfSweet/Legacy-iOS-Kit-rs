use legacy_ios_core::{DeviceMode, Ecid};
use legacy_ios_exploits::Limera1n;
use legacy_ios_transport::{IbootClient, RecoveryDeviceInfo, UploadResult};

use crate::KitError;

#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryManager;

impl RecoveryManager {
    pub async fn open(&self, ecid: Option<Ecid>) -> Result<RecoveryDevice, KitError> {
        Ok(RecoveryDevice {
            client: IbootClient::open(ecid).await?,
        })
    }
}

pub struct RecoveryDevice {
    client: IbootClient,
}

impl RecoveryDevice {
    pub const fn mode(&self) -> DeviceMode {
        self.client.mode()
    }

    pub fn info(&self) -> &RecoveryDeviceInfo {
        self.client.device_info()
    }

    pub async fn send_command(&self, command: &str) -> Result<(), KitError> {
        self.client.send_command(command).await?;
        Ok(())
    }

    pub async fn reboot_to_normal(&self) -> Result<(), KitError> {
        self.client.reboot_to_normal().await?;
        Ok(())
    }

    pub async fn upload_payload(&mut self, data: &[u8]) -> Result<(), KitError> {
        self.client.upload_payload(data).await?;
        Ok(())
    }

    pub async fn upload_image(self, data: &[u8]) -> Result<RecoveryUploadResult, KitError> {
        match self.client.upload_image(data).await? {
            UploadResult::Connected(client) => {
                Ok(RecoveryUploadResult::Connected(Box::new(RecoveryDevice {
                    client: *client,
                })))
            }
            UploadResult::Reenumerating => Ok(RecoveryUploadResult::Reenumerating),
        }
    }

    pub async fn reset(self) -> Result<(), KitError> {
        self.client.reset().await?;
        Ok(())
    }

    pub async fn limera1n(self, payload: Vec<u8>) -> Result<Self, KitError> {
        let client = Limera1n::new(payload)?.exploit(self.client).await?;
        Ok(Self { client })
    }
}

pub enum RecoveryUploadResult {
    Connected(Box<RecoveryDevice>),
    Reenumerating,
}
