use std::io::Cursor;

use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub struct PlistFramed<S> {
    stream: S,
}

impl<S> PlistFramed<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub async fn send(&mut self, dictionary: &Dictionary) -> Result<(), PlistFrameError> {
        let mut payload = Vec::new();
        Value::Dictionary(dictionary.clone()).to_writer_xml(&mut payload)?;
        let length = u32::try_from(payload.len()).map_err(|_| PlistFrameError::FrameTooLarge {
            size: payload.len(),
            maximum: u32::MAX as usize,
        })?;
        trace!(
            bytes = payload.len(),
            keys = dictionary.len(),
            "sending plist frame"
        );
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&payload).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Dictionary, PlistFrameError> {
        let length = self.stream.read_u32().await? as usize;
        if length > MAX_FRAME_SIZE {
            return Err(PlistFrameError::FrameTooLarge {
                size: length,
                maximum: MAX_FRAME_SIZE,
            });
        }
        let mut payload = vec![0; length];
        self.stream.read_exact(&mut payload).await?;
        let value = Value::from_reader(Cursor::new(payload))?;
        let dictionary = value
            .into_dictionary()
            .ok_or(PlistFrameError::NotDictionary)?;
        trace!(
            bytes = length,
            keys = dictionary.len(),
            "received plist frame"
        );
        Ok(dictionary)
    }
}

#[derive(Debug, Error)]
pub enum PlistFrameError {
    #[error("plist stream I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid plist frame: {0}")]
    Plist(#[from] plist::Error),
    #[error("plist frame is {size} bytes, exceeding the {maximum} byte limit")]
    FrameTooLarge { size: usize, maximum: usize },
    #[error("plist frame root is not a dictionary")]
    NotDictionary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_dictionary_frames() {
        let (left, right) = tokio::io::duplex(4096);
        let mut writer = PlistFramed::new(left);
        let mut reader = PlistFramed::new(right);
        let mut dictionary = Dictionary::new();
        dictionary.insert("MsgType".into(), "StatusMsg".into());
        dictionary.insert("Status".into(), 0_u64.into());

        let send = writer.send(&dictionary);
        let receive = reader.receive();
        let (sent, received) = tokio::join!(send, receive);

        sent.unwrap();
        assert_eq!(received.unwrap(), dictionary);
    }
}
