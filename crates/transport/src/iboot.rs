use std::time::Duration;

use legacy_ios_core::{DeviceMode, Ecid};
use nusb::{
    Device, Interface,
    transfer::{
        Buffer, Bulk, ControlIn, ControlOut, ControlType, In, Interrupt, Out, Recipient,
        TransferError,
    },
};
use thiserror::Error;
use tracing::{debug, trace};

use crate::{RecoveryDeviceInfo, classify_apple_mode, parse_iboot_serial};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const KIS_PORTAL_CONFIG: u8 = 0x01;
const KIS_PORTAL_RSM: u8 = 0x10;
const KIS_INDEX_UPLOAD: u16 = 0x0d;
const KIS_INDEX_ENABLE_A: u16 = 0x0a;
const KIS_INDEX_ENABLE_B: u16 = 0x14;
const KIS_INDEX_BOOT_IMAGE: u16 = 0x103;
const KIS_CHUNK_SIZE: usize = 0x4000;

pub struct IbootClient {
    device: Device,
    interface: Interface,
    mode: DeviceMode,
    info: RecoveryDeviceInfo,
}

pub enum UploadResult {
    Connected(Box<IbootClient>),
    Reenumerating,
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
            return self.send_legacy_command(command).await;
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

    pub async fn upload_payload(&mut self, data: &[u8]) -> Result<(), RecoveryError> {
        self.upload(data, false).await
    }

    pub async fn upload_image(mut self, data: &[u8]) -> Result<UploadResult, RecoveryError> {
        if self.uses_ios1_protocol() {
            self.upload_ios1(data).await?;
            let length = data.len();
            let _ = self.device.reset().await;
            drop(self);
            let client = reconnect_legacy().await?;
            client
                .send_command(&format!("setenv filesize {length}"))
                .await?;
            return Ok(UploadResult::Connected(Box::new(client)));
        }
        let reenumerates = matches!(
            self.mode,
            DeviceMode::Dfu | DeviceMode::Wtf | DeviceMode::Kis
        ) || self.uses_ios2_upload();
        self.upload(data, reenumerates).await?;
        if reenumerates {
            if self.mode != DeviceMode::Kis {
                self.device.reset().await?;
            }
            Ok(UploadResult::Reenumerating)
        } else {
            Ok(UploadResult::Connected(Box::new(self)))
        }
    }

    pub async fn reset(self) -> Result<(), RecoveryError> {
        self.device.reset().await?;
        Ok(())
    }

    pub async fn exploit_control_out(
        &self,
        request: u8,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), RecoveryError> {
        if self.mode != DeviceMode::Dfu {
            return Err(RecoveryError::ExploitRequiresDfu(self.mode));
        }
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request,
                    value: 0,
                    index: 0,
                    data,
                },
                timeout,
            )
            .await?;
        Ok(())
    }

    pub async fn exploit_control_in(
        &self,
        request: u8,
        length: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, RecoveryError> {
        if self.mode != DeviceMode::Dfu {
            return Err(RecoveryError::ExploitRequiresDfu(self.mode));
        }
        Ok(self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request,
                    value: 0,
                    index: 0,
                    length,
                },
                timeout,
            )
            .await?)
    }

    async fn upload(&mut self, data: &[u8], finish_dfu: bool) -> Result<(), RecoveryError> {
        if data.is_empty() {
            return Err(RecoveryError::EmptyUpload);
        }
        match self.mode {
            DeviceMode::Recovery if self.uses_ios2_upload() => {
                self.upload_dfu(data, true, true).await
            }
            DeviceMode::Recovery => self.upload_recovery(data).await,
            DeviceMode::Dfu | DeviceMode::Wtf => self.upload_dfu(data, finish_dfu, false).await,
            DeviceMode::Kis => self.upload_kis(data, finish_dfu).await,
            mode => Err(RecoveryError::UploadRequiresBootloader(mode)),
        }
    }

    async fn upload_recovery(&self, data: &[u8]) -> Result<(), RecoveryError> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Interface,
                    request: 0,
                    value: 0,
                    index: 0,
                    data: &[],
                },
                CONTROL_TIMEOUT,
            )
            .await?;

        let mut endpoint = self.interface.endpoint::<Bulk, Out>(0x04)?;
        for chunk in data.chunks(0x8000) {
            send_bulk(&mut endpoint, chunk.to_vec()).await?;
        }
        if data.len().is_multiple_of(512) {
            send_bulk(&mut endpoint, Vec::new()).await?;
        }
        Ok(())
    }

    async fn upload_kis(&self, data: &[u8], boot: bool) -> Result<(), RecoveryError> {
        self.kis_write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_A, 0x21)
            .await?;
        self.kis_write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_B, 0x01)
            .await?;

        let mut address = 0_u64;
        for (index, chunk) in data.chunks(KIS_CHUNK_SIZE).enumerate() {
            let request = kis_upload_request(address, chunk)?;
            self.kis_request(KIS_PORTAL_RSM, request, 20).await?;
            trace!(index, bytes = chunk.len(), "sending KIS upload chunk");
            address += chunk.len() as u64;
        }
        if boot {
            let length = u32::try_from(data.len()).map_err(|_| RecoveryError::KisImageTooLarge)?;
            self.kis_write32(KIS_PORTAL_RSM, KIS_INDEX_BOOT_IMAGE, length)
                .await?;
        }
        Ok(())
    }

    async fn kis_write32(&self, portal: u8, index: u16, value: u32) -> Result<(), RecoveryError> {
        let mut request = kis_request_header(portal, index, 1, 0, 1)?;
        request.extend_from_slice(&value.to_le_bytes());
        let reply = self.kis_request(portal, request, 20).await?;
        if reply.len() < 20 {
            return Err(RecoveryError::InvalidKisReply);
        }
        let written = u32::from_le_bytes(
            reply[12..16]
                .try_into()
                .map_err(|_| RecoveryError::InvalidKisReply)?,
        );
        let status = u32::from_le_bytes(
            reply[16..20]
                .try_into()
                .map_err(|_| RecoveryError::InvalidKisReply)?,
        );
        if written != 4 || status != 0 {
            return Err(RecoveryError::KisRequestRejected { status });
        }
        Ok(())
    }

    async fn kis_request(
        &self,
        portal: u8,
        request: Vec<u8>,
        reply_length: usize,
    ) -> Result<Vec<u8>, RecoveryError> {
        let endpoint = match portal {
            KIS_PORTAL_CONFIG => 0x01,
            KIS_PORTAL_RSM => 0x03,
            _ => return Err(RecoveryError::InvalidKisPortal(portal)),
        };
        let mut output = self.interface.endpoint::<Bulk, Out>(endpoint)?;
        send_bulk(&mut output, request).await?;
        let mut input = self.interface.endpoint::<Bulk, In>(endpoint | 0x80)?;
        input.submit(Buffer::new(reply_length));
        let completion = tokio::time::timeout(CONTROL_TIMEOUT, input.next_complete())
            .await
            .map_err(|_| RecoveryError::TransferTimeout)?;
        Ok(completion.into_result()?.into_vec())
    }

    async fn send_legacy_command(&self, command: &str) -> Result<(), RecoveryError> {
        let command_length = command.len();
        if command_length == 0 {
            return Ok(());
        }
        self.probe_legacy_protocol().await?;
        let transfer_length = command_length.next_multiple_of(16);
        let message = legacy_message(0x803, transfer_length as u32, 0);
        self.interrupt_out(0x04, &message).await?;
        let reply = self.interrupt_in(0x83, 0x100).await?;
        if reply.get(..2) != Some(0x0808_u16.to_le_bytes().as_slice()) {
            return Err(RecoveryError::LegacyCommandRejected);
        }
        let mut payload = vec![0; transfer_length];
        payload[..command_length].copy_from_slice(command.as_bytes());
        if command_length < transfer_length {
            payload[command_length] = b'\n';
        }
        self.interrupt_out(0x02, &payload).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(())
    }

    async fn upload_ios1(&self, data: &[u8]) -> Result<(), RecoveryError> {
        if data.is_empty() {
            return Err(RecoveryError::EmptyUpload);
        }
        self.probe_legacy_protocol().await?;
        let message = legacy_message(0x805, data.len() as u32, 0x0900_0000);
        self.interrupt_out(0x04, &message).await?;
        let reply = self.interrupt_in(0x83, 0x100).await?;
        if reply.get(..2) != Some(0x0808_u16.to_le_bytes().as_slice()) {
            return Err(RecoveryError::LegacyCommandRejected);
        }
        for chunk in data.chunks(0x200) {
            self.interrupt_out(0x05, chunk).await?;
        }
        Ok(())
    }

    async fn probe_legacy_protocol(&self) -> Result<(), RecoveryError> {
        self.interrupt_out(0x04, &[0, 0, 0x34, 0x12]).await?;
        let response = self.interrupt_in(0x83, 0x100).await?;
        if response.len() != 12 {
            return Err(RecoveryError::LegacyProtocolProbe(response.len()));
        }
        Ok(())
    }

    async fn interrupt_out(&self, address: u8, data: &[u8]) -> Result<(), RecoveryError> {
        let mut endpoint = self.interface.endpoint::<Interrupt, Out>(address)?;
        send_interrupt(&mut endpoint, data.to_vec()).await
    }

    async fn interrupt_in(&self, address: u8, length: usize) -> Result<Vec<u8>, RecoveryError> {
        let mut endpoint = self.interface.endpoint::<Interrupt, In>(address)?;
        endpoint.submit(Buffer::new(length));
        let completion = tokio::time::timeout(CONTROL_TIMEOUT, endpoint.next_complete())
            .await
            .map_err(|_| RecoveryError::TransferTimeout)?;
        Ok(completion.into_result()?.into_vec())
    }

    async fn upload_dfu(
        &self,
        data: &[u8],
        finish: bool,
        allow_wait_reset: bool,
    ) -> Result<(), RecoveryError> {
        self.prepare_dfu_download(allow_wait_reset).await?;

        let suffix = [
            0xff, 0xff, 0xff, 0xff, 0xac, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10,
        ];
        let crc = data
            .iter()
            .chain(suffix.iter())
            .fold(0xffff_ffff, |crc, byte| crc32_step(crc, *byte));
        let mut blocks = data
            .chunks(0x800)
            .enumerate()
            .map(|(index, chunk)| (index as u16, chunk.to_vec()))
            .collect::<Vec<_>>();
        let packet_count = blocks.len() as u16;

        let last_index = blocks.len() - 1;
        if blocks[last_index].1.len() + 16 <= 0x800 {
            blocks[last_index].1.extend_from_slice(&suffix);
            blocks[last_index].1.extend_from_slice(&crc.to_le_bytes());
        } else {
            let mut trailer = suffix.to_vec();
            trailer.extend_from_slice(&crc.to_le_bytes());
            blocks.push((last_index as u16, trailer));
        }

        for (index, block) in &blocks {
            trace!(index, bytes = block.len(), "sending DFU download block");
            self.dfu_download(*index, block).await?;
            self.wait_for_dfu_download_idle().await?;
        }

        if finish {
            self.dfu_download(packet_count, &[]).await?;
            self.get_dfu_status().await?;
            self.get_dfu_status().await?;
        }
        Ok(())
    }

    async fn prepare_dfu_download(&self, allow_wait_reset: bool) -> Result<(), RecoveryError> {
        let state = self.get_dfu_state().await?;
        match state {
            2 => Ok(()),
            8 if allow_wait_reset => Ok(()),
            8 => {
                self.dfu_abort().await?;
                Err(RecoveryError::UnexpectedDfuState(state))
            }
            10 => {
                self.dfu_clear_status().await?;
                Err(RecoveryError::UnexpectedDfuState(state))
            }
            _ => {
                self.dfu_abort().await?;
                Err(RecoveryError::UnexpectedDfuState(state))
            }
        }
    }

    fn uses_ios2_upload(&self) -> bool {
        if self.mode != DeviceMode::Recovery || self.info.ibfl().is_some() {
            return false;
        }
        match self.info.effective_cpid() {
            0x8720 => true,
            0x8900 => self.info.ecid().is_some(),
            _ => false,
        }
    }

    fn uses_ios1_protocol(&self) -> bool {
        self.mode == DeviceMode::Recovery
            && self.info.effective_cpid() == 0x8900
            && self.info.ecid().is_none()
    }

    async fn get_dfu_state(&self) -> Result<u8, RecoveryError> {
        let data = self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 5,
                    value: 0,
                    index: 0,
                    length: 1,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        data.first().copied().ok_or(RecoveryError::MissingDfuState)
    }

    async fn get_dfu_status(&self) -> Result<u8, RecoveryError> {
        let data = self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 3,
                    value: 0,
                    index: 0,
                    length: 6,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        data.get(4).copied().ok_or(RecoveryError::MissingDfuStatus)
    }

    async fn wait_for_dfu_download_idle(&self) -> Result<(), RecoveryError> {
        for attempt in 0..=20 {
            let status = self.get_dfu_status().await?;
            if status == 5 {
                return Ok(());
            }
            if attempt != 20 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        Err(RecoveryError::DfuDownloadDidNotBecomeIdle)
    }

    async fn dfu_download(&self, block: u16, data: &[u8]) -> Result<(), RecoveryError> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 1,
                    value: block,
                    index: 0,
                    data,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    async fn dfu_abort(&self) -> Result<(), RecoveryError> {
        self.dfu_control(6).await
    }

    async fn dfu_clear_status(&self) -> Result<(), RecoveryError> {
        self.dfu_control(4).await
    }

    async fn dfu_control(&self, request: u8) -> Result<(), RecoveryError> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request,
                    value: 0,
                    index: 0,
                    data: &[],
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        Ok(())
    }
}

async fn reconnect_legacy() -> Result<IbootClient, RecoveryError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(7);
    loop {
        match IbootClient::open(None).await {
            Ok(client) => return Ok(client),
            Err(RecoveryError::NoDevice) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn legacy_message(command: u16, size: u32, load_address: u32) -> [u8; 12] {
    let mut message = [0; 12];
    message[..2].copy_from_slice(&command.to_le_bytes());
    message[2..4].copy_from_slice(&0x1234_u16.to_le_bytes());
    message[4..8].copy_from_slice(&size.to_le_bytes());
    message[8..].copy_from_slice(&load_address.to_le_bytes());
    message
}

async fn send_bulk(
    endpoint: &mut nusb::Endpoint<Bulk, Out>,
    data: Vec<u8>,
) -> Result<(), RecoveryError> {
    let expected = data.len();
    endpoint.submit(Buffer::from(data));
    let completion = tokio::time::timeout(CONTROL_TIMEOUT, endpoint.next_complete())
        .await
        .map_err(|_| RecoveryError::TransferTimeout)?;
    completion.status?;
    if completion.actual_len != expected {
        return Err(RecoveryError::ShortTransfer {
            expected,
            actual: completion.actual_len,
        });
    }
    trace!(bytes = expected, "completed recovery bulk transfer");
    Ok(())
}

async fn send_interrupt(
    endpoint: &mut nusb::Endpoint<Interrupt, Out>,
    data: Vec<u8>,
) -> Result<(), RecoveryError> {
    let expected = data.len();
    endpoint.submit(Buffer::from(data));
    let completion = tokio::time::timeout(CONTROL_TIMEOUT, endpoint.next_complete())
        .await
        .map_err(|_| RecoveryError::TransferTimeout)?;
    completion.status?;
    if completion.actual_len != expected {
        return Err(RecoveryError::ShortTransfer {
            expected,
            actual: completion.actual_len,
        });
    }
    trace!(bytes = expected, "completed legacy interrupt transfer");
    Ok(())
}

fn crc32_step(crc: u32, byte: u8) -> u32 {
    let mut low = (crc ^ u32::from(byte)) & 0xff;
    for _ in 0..8 {
        low = if low & 1 == 1 {
            0xedb8_8320 ^ (low >> 1)
        } else {
            low >> 1
        };
    }
    low ^ (crc >> 8)
}

fn command_request(command: &str) -> u8 {
    match command {
        "go" | "bootx" | "reboot" | "memboot" => 1,
        _ => 0,
    }
}

fn kis_request_header(
    portal: u8,
    index: u16,
    argument_count: u8,
    payload_size: usize,
    reply_words: u16,
) -> Result<Vec<u8>, RecoveryError> {
    if index >= 1 << 10 || reply_words >= 1 << 14 {
        return Err(RecoveryError::InvalidKisRequest);
    }
    let request_size = payload_size
        .checked_add(usize::from(argument_count) * 4)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(RecoveryError::InvalidKisRequest)?;
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&0_u16.to_le_bytes());
    header.push(0xa0);
    header.push(portal);
    header.push(argument_count);
    header.push(index as u8);
    header.push(((index >> 8) as u8 & 0x03) | ((reply_words << 2) as u8 & 0xfc));
    header.push((reply_words >> 6) as u8);
    header.extend_from_slice(&request_size.to_le_bytes());
    Ok(header)
}

fn kis_upload_request(address: u64, data: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    let mut request = kis_request_header(KIS_PORTAL_RSM, KIS_INDEX_UPLOAD, 3, data.len(), 0)?;
    request.extend_from_slice(&address.to_le_bytes());
    request.extend_from_slice(
        &u32::try_from(data.len())
            .map_err(|_| RecoveryError::InvalidKisRequest)?
            .to_le_bytes(),
    );
    request.extend_from_slice(data);
    Ok(request)
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
    #[error("early iBoot protocol probe returned {0} bytes instead of 12")]
    LegacyProtocolProbe(usize),
    #[error("early iBoot rejected the command or file transfer")]
    LegacyCommandRejected,
    #[error("KIS request is invalid")]
    InvalidKisRequest,
    #[error("KIS portal {0:#04x} is invalid")]
    InvalidKisPortal(u8),
    #[error("KIS device returned an invalid reply")]
    InvalidKisReply,
    #[error("KIS device rejected the request with status {status:#010x}")]
    KisRequestRejected { status: u32 },
    #[error("KIS image exceeds the protocol size limit")]
    KisImageTooLarge,
    #[error("image upload requires a bootloader mode, found {0:?}")]
    UploadRequiresBootloader(DeviceMode),
    #[error("bootrom exploit transfers require DFU mode, found {0:?}")]
    ExploitRequiresDfu(DeviceMode),
    #[error("cannot upload an empty image")]
    EmptyUpload,
    #[error("DFU state response was empty")]
    MissingDfuState,
    #[error("DFU status response was incomplete")]
    MissingDfuStatus,
    #[error("unexpected DFU state {0}")]
    UnexpectedDfuState(u8),
    #[error("DFU download did not return to idle")]
    DfuDownloadDidNotBecomeIdle,
    #[error("USB transfer timed out")]
    TransferTimeout,
    #[error("short USB transfer: expected {expected} bytes, transferred {actual}")]
    ShortTransfer { expected: usize, actual: usize },
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

    #[test]
    fn crc_step_matches_standard_reflected_crc32() {
        let crc = b"123456789"
            .iter()
            .fold(0xffff_ffff, |crc, byte| crc32_step(crc, *byte));
        assert_eq!(!crc, 0xcbf4_3926);
    }

    #[test]
    fn encodes_legacy_file_message() {
        assert_eq!(
            legacy_message(0x805, 0x1234, 0x0900_0000),
            [0x05, 0x08, 0x34, 0x12, 0x34, 0x12, 0, 0, 0, 0, 0, 9]
        );
    }

    #[test]
    fn encodes_kis_upload_request() {
        let request = kis_upload_request(0x1122_3344_5566_7788, &[1, 2, 3]).unwrap();

        assert_eq!(request.len(), 27);
        assert_eq!(&request[..8], &[0, 0, 0xa0, 0x10, 3, 0x0d, 0, 0]);
        assert_eq!(&request[8..12], &15_u32.to_le_bytes());
        assert_eq!(&request[12..20], &0x1122_3344_5566_7788_u64.to_le_bytes());
        assert_eq!(&request[20..24], &3_u32.to_le_bytes());
        assert_eq!(&request[24..], &[1, 2, 3]);
    }
}
