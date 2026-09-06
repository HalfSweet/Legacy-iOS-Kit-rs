//! System usbmux RPCs without payload logging. Pair records must never reach
//! the dependency's debug-level plist logger.

use std::io::Cursor;

use idevice::{
    pairing_file::PairingFile,
    usbmuxd::{Connection, UsbmuxdDevice},
};
use legacy_ios_transport::{SystemMuxSocket, connect_system_mux};
use plist::{Dictionary, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ServiceError;
use zeroize::{Zeroize, Zeroizing};

const HEADER_SIZE: u32 = 16;
const MAX_MESSAGE: u32 = 4 * 1024 * 1024;

pub(crate) async fn list() -> Result<Vec<UsbmuxdDevice>, ServiceError> {
    let response = rpc("ListDevices", Dictionary::new()).await?;
    let entries = response
        .get("DeviceList")
        .and_then(Value::as_array)
        .ok_or(ServiceError::UnexpectedValue("DeviceList"))?;
    let mut devices = vec![];
    for entry in entries {
        let entry = entry
            .as_dictionary()
            .ok_or(ServiceError::UnexpectedValue("DeviceList"))?;
        let properties = entry
            .get("Properties")
            .and_then(Value::as_dictionary)
            .ok_or(ServiceError::UnexpectedValue("Properties"))?;
        if properties.get("ConnectionType").and_then(Value::as_string) != Some("USB") {
            continue;
        }
        let udid = properties
            .get("SerialNumber")
            .and_then(Value::as_string)
            .ok_or(ServiceError::MissingUdid)?
            .to_owned();
        let device_id = entry
            .get("DeviceID")
            .and_then(Value::as_unsigned_integer)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ServiceError::UnexpectedValue("DeviceID"))?;
        devices.push(UsbmuxdDevice {
            connection_type: Connection::Usb,
            udid,
            device_id,
        });
    }
    Ok(devices)
}

pub(crate) async fn pairing(udid: &str) -> Result<PairingFile, ServiceError> {
    let mut response = rpc(
        "ReadPairRecord",
        Dictionary::from_iter([("PairRecordID", Value::String(udid.into()))]),
    )
    .await?;
    let bytes = response
        .remove("PairRecordData")
        .and_then(Value::into_data)
        .ok_or(ServiceError::Idevice(idevice::IdeviceError::InvalidHostID))?;
    Ok(PairingFile::from_bytes(&Zeroizing::new(bytes))?)
}

pub(crate) async fn buid() -> Result<String, ServiceError> {
    rpc("ReadBUID", Dictionary::new())
        .await?
        .remove("BUID")
        .and_then(Value::into_string)
        .ok_or(ServiceError::UnexpectedValue("BUID"))
}

pub(crate) async fn save_pairing(udid: &str, bytes: Vec<u8>) -> Result<(), ServiceError> {
    rpc(
        "SavePairRecord",
        Dictionary::from_iter([
            ("PairRecordID", Value::String(udid.into())),
            ("PairRecordData", Value::Data(bytes)),
        ]),
    )
    .await?;
    Ok(())
}

async fn rpc(kind: &'static str, mut fields: Dictionary) -> Result<Dictionary, ServiceError> {
    fields.insert("MessageType".into(), kind.into());
    fields.insert("ClientVersionString".into(), "legacy-ios-kit".into());
    fields.insert("ProgName".into(), "legacy-ios-kit".into());
    fields.insert("kLibUSBMuxVersion".into(), 3u64.into());
    let mut stream: SystemMuxSocket = connect_system_mux().await?;
    exchange(&mut stream, fields).await
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: Dictionary,
) -> Result<Dictionary, ServiceError> {
    let mut request = Value::Dictionary(request);
    let mut bytes = Zeroizing::new(vec![]);
    request.to_writer_xml(&mut *bytes)?;
    if let Some(Value::Data(data)) = request
        .as_dictionary_mut()
        .and_then(|fields| fields.get_mut("PairRecordData"))
    {
        data.zeroize();
    }
    let length = u32::try_from(bytes.len())
        .ok()
        .and_then(|length| length.checked_add(HEADER_SIZE))
        .filter(|length| *length <= MAX_MESSAGE)
        .ok_or(ServiceError::FrameTooLarge)?;
    for field in [length, 1, 8, 1] {
        stream.write_u32_le(field).await?;
    }
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let length = stream.read_u32_le().await?;
    let version = stream.read_u32_le().await?;
    let message = stream.read_u32_le().await?;
    let tag = stream.read_u32_le().await?;
    if !(HEADER_SIZE..=MAX_MESSAGE).contains(&length) {
        return Err(ServiceError::FrameTooLarge);
    }
    if version != 1 || message != 8 || tag != 1 {
        return Err(ServiceError::UnexpectedValue("usbmux header"));
    }
    let mut bytes = Zeroizing::new(vec![0; (length - HEADER_SIZE) as usize]);
    stream.read_exact(&mut bytes).await?;
    let response = Value::from_reader(Cursor::new(bytes.as_slice()))?
        .into_dictionary()
        .ok_or(ServiceError::PlistNotDictionary)?;
    if let Some(number) = response.get("Number").and_then(Value::as_unsigned_integer) {
        if number != 0 {
            return Err(ServiceError::MuxRequestRejected(number));
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_unmatched_tags_before_parsing_a_pairing_record() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let length = server.read_u32_le().await.unwrap();
            let mut rest = vec![0; length as usize - 4];
            server.read_exact(&mut rest).await.unwrap();
            for field in [HEADER_SIZE, 1, 8, 99] {
                server.write_u32_le(field).await.unwrap();
            }
        });
        assert!(matches!(
            exchange(&mut client, Dictionary::new()).await,
            Err(ServiceError::UnexpectedValue("usbmux header"))
        ));
        peer.await.unwrap();
    }
}
