//! Bounded AFC exchanges without an asynchronously closing file-descriptor
//! destructor. Dropping a timed-out stream simply ends its session; it never
//! panics, sends a second exchange, or attempts to delete an in-use package.
use super::AppFailure;
use crate::ServiceError;
use idevice::{
    IdeviceError,
    services::afc::{
        MAGIC,
        errors::AfcError,
        opcode::{AfcFopenMode, AfcOpcode},
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) struct StagingClient<S> {
    stream: S,
    sequence: u64,
}
impl<S: AsyncRead + AsyncWrite + Unpin> StagingClient<S> {
    pub(super) fn new(stream: S) -> Self {
        Self {
            stream,
            sequence: 0,
        }
    }
    async fn exchange(
        &mut self,
        operation: AfcOpcode,
        header: Vec<u8>,
        body: &[u8],
    ) -> Result<(AfcOpcode, Vec<u8>), ServiceError> {
        let sequence = self.sequence;
        self.sequence += 1;
        for value in [
            MAGIC,
            40 + header.len() as u64 + body.len() as u64,
            40 + header.len() as u64,
            sequence,
            operation as u64,
        ] {
            self.stream.write_u64_le(value).await?;
        }
        self.stream.write_all(&header).await?;
        self.stream.write_all(body).await?;
        self.stream.flush().await?;
        let magic = self.stream.read_u64_le().await?;
        let total = self.stream.read_u64_le().await?;
        let header_size = self.stream.read_u64_le().await?;
        let response_sequence = self.stream.read_u64_le().await?;
        let operation = self.stream.read_u64_le().await?;
        if magic != MAGIC
            || response_sequence != sequence
            || !(40..=64 * 1024).contains(&total)
            || !(40..=total).contains(&header_size)
        {
            return Err(AppFailure::InvalidResponse.into());
        }
        let operation = AfcOpcode::try_from(operation).map_err(|_| AppFailure::InvalidResponse)?;
        let mut response = vec![0; (total - 40) as usize];
        self.stream.read_exact(&mut response).await?;
        if operation == AfcOpcode::Status {
            let status = u64::from_le_bytes(
                response
                    .as_slice()
                    .try_into()
                    .map_err(|_| AppFailure::InvalidResponse)?,
            );
            if status != 0 {
                return Err(IdeviceError::Afc(AfcError::from(status)).into());
            }
        }
        Ok((operation, response))
    }
    async fn status(
        &mut self,
        operation: AfcOpcode,
        header: Vec<u8>,
        body: &[u8],
    ) -> Result<(), ServiceError> {
        let (operation, _) = self.exchange(operation, header, body).await?;
        if operation != AfcOpcode::Status {
            return Err(AppFailure::InvalidResponse.into());
        }
        Ok(())
    }
    pub(super) async fn create_directory(&mut self) -> Result<(), ServiceError> {
        match self
            .status(AfcOpcode::MakeDir, b"/PublicStaging\0".to_vec(), &[])
            .await
        {
            Ok(()) | Err(ServiceError::Idevice(IdeviceError::Afc(AfcError::ObjectExists))) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    pub(super) async fn open(&mut self, path: &str) -> Result<u64, ServiceError> {
        let mut header = (AfcFopenMode::WrOnly as u64).to_le_bytes().to_vec();
        header.extend(path.bytes());
        header.push(0);
        let (operation, response) = self.exchange(AfcOpcode::FileOpen, header, &[]).await?;
        if operation != AfcOpcode::FileOpenRes {
            return Err(AppFailure::InvalidResponse.into());
        }
        Ok(u64::from_le_bytes(
            response
                .as_slice()
                .try_into()
                .map_err(|_| AppFailure::InvalidResponse)?,
        ))
    }
    pub(super) async fn write(&mut self, fd: u64, bytes: &[u8]) -> Result<(), ServiceError> {
        self.status(AfcOpcode::Write, fd.to_le_bytes().to_vec(), bytes)
            .await
    }
    pub(super) async fn close(&mut self, fd: u64) -> Result<(), ServiceError> {
        self.status(AfcOpcode::FileClose, fd.to_le_bytes().to_vec(), &[])
            .await
    }
    pub(super) async fn remove(&mut self, path: &str) -> Result<(), ServiceError> {
        let mut header = path.as_bytes().to_vec();
        header.push(0);
        match self.status(AfcOpcode::RemovePath, header, &[]).await {
            Ok(()) | Err(ServiceError::Idevice(IdeviceError::Afc(AfcError::ObjectNotFound))) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn request(
        peer: &mut tokio::io::DuplexStream,
        expected: AfcOpcode,
        sequence: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        assert_eq!(peer.read_u64_le().await.unwrap(), MAGIC);
        let total = peer.read_u64_le().await.unwrap();
        let header = peer.read_u64_le().await.unwrap();
        assert_eq!(peer.read_u64_le().await.unwrap(), sequence);
        assert_eq!(peer.read_u64_le().await.unwrap(), expected as u64);
        let mut arguments = vec![0; (header - 40) as usize];
        peer.read_exact(&mut arguments).await.unwrap();
        let mut body = vec![0; (total - header) as usize];
        peer.read_exact(&mut body).await.unwrap();
        (arguments, body)
    }
    async fn response(
        peer: &mut tokio::io::DuplexStream,
        sequence: u64,
        operation: AfcOpcode,
        value: u64,
    ) {
        for value in [MAGIC, 48, 48, sequence, operation as u64, value] {
            peer.write_u64_le(value).await.unwrap();
        }
    }
    #[tokio::test]
    async fn staging_transcript_and_missing_file_cleanup() {
        let (host, mut peer) = tokio::io::duplex(8192);
        let device = tokio::spawn(async move {
            assert_eq!(
                request(&mut peer, AfcOpcode::MakeDir, 0).await.0,
                b"/PublicStaging\0"
            );
            response(&mut peer, 0, AfcOpcode::Status, 16).await;
            let (arguments, _) = request(&mut peer, AfcOpcode::FileOpen, 1).await;
            assert_eq!(
                &arguments[..8],
                &(AfcFopenMode::WrOnly as u64).to_le_bytes()
            );
            assert_eq!(&arguments[8..], b"/PublicStaging/operation.ipa\0");
            response(&mut peer, 1, AfcOpcode::FileOpenRes, 7).await;
            let (fd, body) = request(&mut peer, AfcOpcode::Write, 2).await;
            assert_eq!(fd, 7u64.to_le_bytes());
            assert_eq!(body, b"package");
            response(&mut peer, 2, AfcOpcode::Status, 0).await;
            assert_eq!(
                request(&mut peer, AfcOpcode::FileClose, 3).await.0,
                7u64.to_le_bytes()
            );
            response(&mut peer, 3, AfcOpcode::Status, 0).await;
            request(&mut peer, AfcOpcode::RemovePath, 4).await;
            response(&mut peer, 4, AfcOpcode::Status, 8).await;
        });
        let mut client = StagingClient::new(host);
        client.create_directory().await.unwrap();
        let fd = client.open("/PublicStaging/operation.ipa").await.unwrap();
        client.write(fd, b"package").await.unwrap();
        client.close(fd).await.unwrap();
        client.remove("/PublicStaging/operation.ipa").await.unwrap();
        device.await.unwrap();
    }
    #[tokio::test]
    async fn malformed_response_is_bounded_and_disconnect_drops_without_panicking() {
        for total in [39, 64 * 1024 + 1] {
            let (host, mut peer) = tokio::io::duplex(8192);
            let device = tokio::spawn(async move {
                request(&mut peer, AfcOpcode::FileOpen, 0).await;
                for value in [MAGIC, total, 40, 0, AfcOpcode::FileOpenRes as u64] {
                    peer.write_u64_le(value).await.unwrap();
                }
            });
            assert!(matches!(
                StagingClient::new(host)
                    .open("/PublicStaging/test.ipa")
                    .await,
                Err(ServiceError::Application(AppFailure::InvalidResponse))
            ));
            device.await.unwrap();
        }
        let (host, mut peer) = tokio::io::duplex(8192);
        let device = tokio::spawn(async move {
            request(&mut peer, AfcOpcode::FileOpen, 0).await;
            response(&mut peer, 0, AfcOpcode::FileOpenRes, 7).await;
            request(&mut peer, AfcOpcode::Write, 1).await;
        });
        let mut client = StagingClient::new(host);
        let fd = client.open("/PublicStaging/test.ipa").await.unwrap();
        assert!(client.write(fd, b"package").await.is_err());
        drop(client);
        device.await.unwrap();
    }
}
