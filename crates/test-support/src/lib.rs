#![forbid(unsafe_code)]

//! Protocol transcripts and test doubles for meaningful integration tests.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptStep {
    Read(Vec<u8>),
    Write(Vec<u8>),
}

impl TranscriptStep {
    pub fn read(data: impl Into<Vec<u8>>) -> Self {
        Self::Read(data.into())
    }

    pub fn write(data: impl Into<Vec<u8>>) -> Self {
        Self::Write(data.into())
    }
}

#[derive(Debug)]
pub struct TranscriptStream {
    steps: VecDeque<PendingStep>,
}

impl TranscriptStream {
    pub fn new(steps: impl IntoIterator<Item = TranscriptStep>) -> Self {
        Self {
            steps: steps.into_iter().map(PendingStep::from).collect(),
        }
    }

    pub fn remaining_steps(&self) -> usize {
        self.steps.len()
    }

    pub fn finish(self) -> Result<(), TranscriptError> {
        if self.steps.is_empty() {
            Ok(())
        } else {
            Err(TranscriptError::Incomplete(self.steps.len()))
        }
    }
}

#[derive(Debug)]
struct PendingStep {
    direction: Direction,
    data: Vec<u8>,
    offset: usize,
}

impl From<TranscriptStep> for PendingStep {
    fn from(value: TranscriptStep) -> Self {
        match value {
            TranscriptStep::Read(data) => Self {
                direction: Direction::Read,
                data,
                offset: 0,
            },
            TranscriptStep::Write(data) => Self {
                direction: Direction::Write,
                data,
                offset: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Read,
    Write,
}

impl AsyncRead for TranscriptStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let Some(step) = self.steps.front_mut() else {
                return Poll::Ready(Ok(()));
            };
            if step.direction != Direction::Read {
                return Poll::Ready(Err(protocol_error("read occurred before expected write")));
            }
            let remaining = &step.data[step.offset..];
            if remaining.is_empty() {
                self.steps.pop_front();
                continue;
            }
            let length = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..length]);
            step.offset += length;
            if step.offset == step.data.len() {
                self.steps.pop_front();
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for TranscriptStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Some(step) = self.steps.front_mut() else {
            return Poll::Ready(Err(protocol_error("unexpected write after transcript end")));
        };
        if step.direction != Direction::Write {
            return Poll::Ready(Err(protocol_error("write occurred before expected read")));
        }
        let expected = &step.data[step.offset..];
        let length = expected.len().min(buffer.len());
        if expected[..length] != buffer[..length] {
            return Poll::Ready(Err(protocol_error("write did not match transcript")));
        }
        step.offset += length;
        if step.offset == step.data.len() {
            self.steps.pop_front();
        }
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn protocol_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("protocol transcript has {0} unfinished steps")]
    Incomplete(usize),
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn replays_fragmented_reads_and_writes() {
        let mut stream = TranscriptStream::new([
            TranscriptStep::write(b"request".to_vec()),
            TranscriptStep::read(b"response".to_vec()),
        ]);
        stream.write_all(b"req").await.unwrap();
        stream.write_all(b"uest").await.unwrap();
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"response");
        stream.finish().unwrap();
    }
}
