use std::io::Cursor;

use plist::{Dictionary, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ServiceError;

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub(crate) struct PropertyListService<S> {
    stream: S,
}

impl<S> PropertyListService<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(stream: S) -> Self {
        Self { stream }
    }

    pub(crate) async fn send(&mut self, dictionary: &Dictionary) -> Result<(), ServiceError> {
        let mut data = Vec::new();
        Value::Dictionary(dictionary.clone()).to_writer_xml(&mut data)?;
        let length = u32::try_from(data.len()).map_err(|_| ServiceError::FrameTooLarge)?;
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub(crate) async fn receive(&mut self) -> Result<Dictionary, ServiceError> {
        let length = self.stream.read_u32().await? as usize;
        if length > MAX_FRAME_SIZE {
            return Err(ServiceError::FrameTooLarge);
        }
        let mut data = vec![0; length];
        self.stream.read_exact(&mut data).await?;
        Value::from_reader(Cursor::new(data))?
            .into_dictionary()
            .ok_or(ServiceError::PlistNotDictionary)
    }

    /// Hand back the underlying stream, e.g. after a handshake that switches
    /// the connection to a raw byte stream (file_relay).
    pub(crate) fn into_inner(self) -> S {
        self.stream
    }
}
