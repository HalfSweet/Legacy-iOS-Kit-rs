use std::future::Future;

use plist::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use crate::{
    DispatchAction, PreparedRestoreData, RestoreDispatchError, RestoreOptions, RestoredClient,
    RestoredError, RestoredMessage,
};

pub async fn run_restored<S, F, Fut, P>(
    client: &mut RestoredClient<S>,
    options: &RestoreOptions,
    protocol_version: u64,
    prepared: &PreparedRestoreData,
    mut send_system_image: F,
    mut progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    client
        .start_restore(options.to_dictionary(), protocol_version)
        .await?;

    loop {
        match client.next_message().await? {
            RestoredMessage::DataRequest(request) => {
                match prepared.dispatch(request.data_type())? {
                    DispatchAction::SystemImage => send_system_image().await?,
                    DispatchAction::Send(response) => client.send(&response).await?,
                }
            }
            RestoredMessage::Progress(message) => {
                if let (Some(operation), Some(completed)) =
                    (message.operation(), message.progress())
                {
                    progress(RestoreProgress {
                        operation: adapt_operation(operation, protocol_version),
                        completed,
                    });
                }
            }
            RestoredMessage::Status(status) => {
                if let Some(error) = status
                    .message()
                    .get("AMRError")
                    .and_then(Value::as_unsigned_integer)
                {
                    return Err(RestoreRunError::Amr(error));
                }
                match status.status() {
                    Some(0) => return Ok(RestoreOutcome),
                    Some(value @ (6 | 14 | 27 | 51 | 53 | 1015)) => {
                        return Err(RestoreRunError::DeviceStatus(value));
                    }
                    Some(value) => debug!(status = value, "received non-terminal restore status"),
                    None => warn!("received restore status without Status value"),
                }
            }
            RestoredMessage::BasebandStatus(status) => {
                if status.message().get("Accepted").and_then(Value::as_boolean) == Some(false) {
                    return Err(RestoreRunError::BasebandRejected);
                }
            }
            RestoredMessage::PreviousRestoreLog(_) => {
                warn!("device reported a previous restore log")
            }
            RestoredMessage::Unknown { message_type, .. } => {
                warn!(message_type, "ignoring unknown restored message")
            }
        }
    }
}

const fn adapt_operation(operation: u64, protocol_version: u64) -> u64 {
    if protocol_version < 14 && operation > 35 {
        operation + 1
    } else {
        operation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreProgress {
    pub operation: u64,
    pub completed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreOutcome;

#[derive(Debug, Error)]
pub enum RestoreRunError {
    #[error(transparent)]
    Restored(#[from] RestoredError),
    #[error(transparent)]
    Dispatch(#[from] RestoreDispatchError),
    #[error("restore failed with AMR error {0}")]
    Amr(u64),
    #[error("restore failed with device status {0}")]
    DeviceStatus(u64),
    #[error("device rejected baseband data")]
    BasebandRejected,
    #[error("system image transfer failed: {0}")]
    SystemImage(String),
}

#[cfg(test)]
mod tests {
    use plist::Dictionary;

    use super::*;
    use crate::PlistFramed;

    #[tokio::test]
    async fn responds_to_ticket_and_finishes_on_zero_status() {
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let mut client = RestoredClient::new(client_stream, "test");
        let server = tokio::spawn(async move {
            let mut framed = PlistFramed::new(server_stream);
            let start = framed.receive().await.unwrap();
            assert_eq!(
                start.get("Request").and_then(Value::as_string),
                Some("StartRestore")
            );

            let mut request = Dictionary::new();
            request.insert("MsgType".into(), "DataRequestMsg".into());
            request.insert("DataType".into(), "RootTicket".into());
            framed.send(&request).await.unwrap();
            let ticket = framed.receive().await.unwrap();
            assert!(ticket.contains_key("RootTicketData"));

            let mut status = Dictionary::new();
            status.insert("MsgType".into(), "StatusMsg".into());
            status.insert("Status".into(), 0_u64.into());
            framed.send(&status).await.unwrap();
        });

        let prepared = PreparedRestoreData::default().with_root_ticket(vec![1, 2, 3]);
        let result = run_restored(
            &mut client,
            &RestoreOptions::erase(),
            15,
            &prepared,
            || async { Ok(()) },
            |_| {},
        )
        .await;
        server.await.unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn adapts_legacy_progress_operations() {
        assert_eq!(adapt_operation(36, 13), 37);
        assert_eq!(adapt_operation(36, 14), 36);
    }
}
