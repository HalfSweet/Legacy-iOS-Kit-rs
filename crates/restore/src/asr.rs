use std::{io::Cursor, path::Path};

use plist::{Dictionary, Value};
use sha1::{Digest as _, Sha1};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, SeekFrom};
use tracing::{debug, trace};

pub const ASR_PORT: u16 = 12345;

const MAX_PLIST_SIZE: usize = 64 * 1024;
const MAX_OOB_SIZE: u64 = 64 * 1024 * 1024;
const CHECKSUM_CHUNK_SIZE: usize = 131_072;
const PAYLOAD_PACKET_SIZE: usize = 1_450;

pub struct AsrClient<S> {
    stream: S,
    checksum_chunks: bool,
    receive_buffer: Vec<u8>,
}

impl<S> AsrClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn initiate(stream: S) -> Result<Self, AsrError> {
        let mut client = Self {
            stream,
            checksum_chunks: false,
            receive_buffer: Vec::new(),
        };
        let message = client.receive_plist().await?;
        if message.get("Command").and_then(Value::as_string) != Some("Initiate") {
            return Err(AsrError::UnexpectedCommand);
        }
        client.checksum_chunks = message
            .get("Checksum Chunks")
            .and_then(Value::as_boolean)
            .unwrap_or(false);
        debug!(
            checksum_chunks = client.checksum_chunks,
            "initialized ASR session"
        );
        Ok(client)
    }

    pub const fn checksum_chunks(&self) -> bool {
        self.checksum_chunks
    }

    pub async fn validate(&mut self, filesystem: &Path) -> Result<(), AsrError> {
        let mut file = tokio::fs::File::open(filesystem).await?;
        let size = file.metadata().await?.len();
        self.send_packet_info(size).await?;

        loop {
            let message = self.receive_plist().await?;
            match message.get("Command").and_then(Value::as_string) {
                Some("Initiate") => {
                    self.checksum_chunks = message
                        .get("Checksum Chunks")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    self.send_packet_info(size).await?;
                }
                Some("OOBData") => self.send_oob(&mut file, &message).await?,
                Some("Payload") => return Ok(()),
                _ => return Err(AsrError::UnexpectedCommand),
            }
        }
    }

    pub async fn send_payload(
        &mut self,
        filesystem: &Path,
        mut progress: impl FnMut(AsrProgress),
    ) -> Result<(), AsrError> {
        let mut file = tokio::fs::File::open(filesystem).await?;
        let total = file.metadata().await?.len();
        let mut transferred = 0_u64;
        let mut chunk_bytes = 0_usize;
        let mut hasher = Sha1::new();
        let mut buffer = vec![0; PAYLOAD_PACKET_SIZE];

        loop {
            let maximum = if self.checksum_chunks {
                (CHECKSUM_CHUNK_SIZE - chunk_bytes).min(PAYLOAD_PACKET_SIZE)
            } else {
                PAYLOAD_PACKET_SIZE
            };
            let read = file.read(&mut buffer[..maximum]).await?;
            if read == 0 {
                break;
            }
            self.send_raw(&buffer[..read]).await?;
            transferred += read as u64;

            if self.checksum_chunks {
                hasher.update(&buffer[..read]);
                chunk_bytes += read;
                if chunk_bytes == CHECKSUM_CHUNK_SIZE {
                    self.send_raw(&hasher.finalize_reset()).await?;
                    chunk_bytes = 0;
                }
            }
            progress(AsrProgress { transferred, total });
        }

        if self.checksum_chunks && chunk_bytes != 0 {
            self.send_raw(&hasher.finalize()).await?;
        }
        Ok(())
    }

    async fn send_packet_info(&mut self, size: u64) -> Result<(), AsrError> {
        let mut payload = Dictionary::new();
        payload.insert("Port".into(), 1_u64.into());
        payload.insert("Size".into(), size.into());

        let mut packet = Dictionary::new();
        if self.checksum_chunks {
            packet.insert(
                "Checksum Chunk Size".into(),
                (CHECKSUM_CHUNK_SIZE as u64).into(),
            );
        }
        packet.insert("FEC Slice Stride".into(), 40_u64.into());
        packet.insert(
            "Packet Payload Size".into(),
            (PAYLOAD_PACKET_SIZE as u64).into(),
        );
        packet.insert("Packets Per FEC".into(), 25_u64.into());
        packet.insert("Payload".into(), payload.into());
        packet.insert("Stream ID".into(), 1_u64.into());
        packet.insert("Version".into(), 1_u64.into());
        self.send_plist(&packet).await
    }

    async fn send_oob(
        &mut self,
        file: &mut tokio::fs::File,
        message: &Dictionary,
    ) -> Result<(), AsrError> {
        let offset = unsigned(message, "OOB Offset")?;
        let length = unsigned(message, "OOB Length")?;
        if length > MAX_OOB_SIZE {
            return Err(AsrError::OobTooLarge(length));
        }
        file.seek(SeekFrom::Start(offset)).await?;
        let mut data = vec![0; length as usize];
        file.read_exact(&mut data).await?;
        self.send_raw(&data).await
    }

    async fn send_plist(&mut self, dictionary: &Dictionary) -> Result<(), AsrError> {
        let mut payload = Vec::new();
        Value::Dictionary(dictionary.clone()).to_writer_xml(&mut payload)?;
        trace!(
            bytes = payload.len(),
            keys = dictionary.len(),
            "sending ASR plist"
        );
        self.send_raw(&payload).await
    }

    async fn receive_plist(&mut self) -> Result<Dictionary, AsrError> {
        const END: &[u8] = b"</plist>";
        loop {
            if let Some(position) = self
                .receive_buffer
                .windows(END.len())
                .position(|value| value == END)
            {
                let end = position + END.len();
                let payload = self.receive_buffer.drain(..end).collect::<Vec<_>>();
                let value = Value::from_reader(Cursor::new(payload))?;
                return value.into_dictionary().ok_or(AsrError::PlistNotDictionary);
            }
            if self.receive_buffer.len() >= MAX_PLIST_SIZE {
                return Err(AsrError::PlistTooLarge);
            }
            let mut buffer = [0; 4096];
            let read = self.stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(AsrError::UnexpectedEof);
            }
            self.receive_buffer.extend_from_slice(&buffer[..read]);
        }
    }

    async fn send_raw(&mut self, data: &[u8]) -> Result<(), AsrError> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        trace!(bytes = data.len(), "sent ASR bytes");
        Ok(())
    }
}

fn unsigned(dictionary: &Dictionary, key: &'static str) -> Result<u64, AsrError> {
    dictionary
        .get(key)
        .and_then(Value::as_unsigned_integer)
        .ok_or(AsrError::MissingValue(key))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsrProgress {
    pub transferred: u64,
    pub total: u64,
}

#[derive(Debug, Error)]
pub enum AsrError {
    #[error("ASR I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ASR plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("ASR plist root is not a dictionary")]
    PlistNotDictionary,
    #[error("ASR plist exceeds 64 KiB")]
    PlistTooLarge,
    #[error("ASR stream ended before a complete plist arrived")]
    UnexpectedEof,
    #[error("ASR sent an unexpected command")]
    UnexpectedCommand,
    #[error("ASR message is missing {0}")]
    MissingValue(&'static str),
    #[error("ASR requested an oversized OOB range of {0} bytes")]
    OobTooLarge(u64),
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    async fn receive_test_plist(stream: &mut tokio::io::DuplexStream) -> Dictionary {
        const END: &[u8] = b"</plist>";
        let mut data = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            data.extend_from_slice(&buffer[..read]);
            if data.windows(END.len()).any(|window| window == END) {
                return Value::from_reader(Cursor::new(data))
                    .unwrap()
                    .into_dictionary()
                    .unwrap();
            }
        }
    }

    async fn send_test_plist(stream: &mut tokio::io::DuplexStream, command: &str, checksums: bool) {
        let mut message = Dictionary::new();
        message.insert("Command".into(), command.into());
        if command == "Initiate" {
            message.insert("Checksum Chunks".into(), checksums.into());
        }
        let mut data = Vec::new();
        Value::Dictionary(message).to_writer_xml(&mut data).unwrap();
        stream.write_all(&data).await.unwrap();
    }

    #[tokio::test]
    async fn reads_initiate_command() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            server_stream
                .write_all(
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Command</key><string>Initiate</string>
<key>Checksum Chunks</key><true/>
</dict></plist>"#,
                )
                .await
                .unwrap();
        });

        let client = AsrClient::initiate(client_stream).await.unwrap();
        server.await.unwrap();
        assert!(client.checksum_chunks());
    }

    #[tokio::test]
    async fn renegotiates_checksum_chunks_during_validation() {
        let (client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            send_test_plist(&mut server_stream, "Initiate", false).await;
            let first = receive_test_plist(&mut server_stream).await;
            assert!(!first.contains_key("Checksum Chunk Size"));

            send_test_plist(&mut server_stream, "Initiate", true).await;
            let second = receive_test_plist(&mut server_stream).await;
            assert_eq!(
                second
                    .get("Checksum Chunk Size")
                    .and_then(Value::as_unsigned_integer),
                Some(CHECKSUM_CHUNK_SIZE as u64)
            );
            send_test_plist(&mut server_stream, "Payload", false).await;
        });
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut client = AsrClient::initiate(client_stream).await.unwrap();

        client.validate(file.path()).await.unwrap();

        server.await.unwrap();
        assert!(client.checksum_chunks());
    }
}
