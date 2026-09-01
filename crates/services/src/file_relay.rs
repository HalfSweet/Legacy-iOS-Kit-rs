//! `com.apple.mobile.file_relay`: the one-shot debug dump service.
//!
//! The device acknowledges a plist request naming one or more sources and
//! then streams back a raw gzipped cpio archive of the requested trees,
//! closing the connection at the end of the stream.

use plist::{Dictionary, Value};
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::{NormalDevice, ServiceError, plist_service::PropertyListService};

const FILE_RELAY: &str = "com.apple.mobile.file_relay";

impl NormalDevice {
    /// Request the given file-relay sources and read the raw dump stream
    /// until the device closes the connection. The payload is a gzipped
    /// cpio archive.
    pub async fn file_relay_dump(&self, sources: &[&str]) -> Result<Vec<u8>, ServiceError> {
        let stream = self.connect_service(FILE_RELAY).await?;
        let mut service = PropertyListService::new(stream);
        let mut request = Dictionary::new();
        request.insert(
            "Sources".into(),
            Value::Array(
                sources
                    .iter()
                    .map(|source| Value::String((*source).to_owned()))
                    .collect(),
            ),
        );
        service.send(&request).await?;
        let response = service.receive().await?;
        if response.get("Status").and_then(Value::as_string) != Some("Acknowledged") {
            let description = response
                .get("Error")
                .and_then(Value::as_string)
                .unwrap_or("the device rejected the file relay request");
            return Err(ServiceError::FileRelayRejected(description.to_owned()));
        }
        let mut dump = Vec::new();
        service.into_inner().read_to_end(&mut dump).await?;
        debug!(bytes = dump.len(), ?sources, "received file relay dump");
        Ok(dump)
    }
}
