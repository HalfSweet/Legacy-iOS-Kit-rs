use std::future::Future;

use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use crate::{
    AsrError, DataRequest, DispatchAction, PreparedRestoreData, RestoreDispatchError,
    RestoreOptions, RestoredClient, RestoredConnectError, RestoredError, RestoredMessage,
    RestoredSession,
};

pub async fn run_restored_session<F, Fut, P>(
    session: &mut RestoredSession,
    options: &RestoreOptions,
    prepared: &PreparedRestoreData,
    send_system_image: F,
    progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    F: FnMut(Option<u16>) -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    let dispatch = |request: DataRequest| {
        std::future::ready(prepared.dispatch(&request).map_err(RestoreRunError::from))
    };
    run_restored_session_with_dispatcher(session, options, dispatch, send_system_image, progress)
        .await
}

pub async fn run_restored_session_with_dispatcher<F, Fut, R, RFut, P>(
    session: &mut RestoredSession,
    options: &RestoreOptions,
    dispatch: R,
    send_system_image: F,
    progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    F: FnMut(Option<u16>) -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    R: FnMut(DataRequest) -> RFut,
    RFut: Future<Output = Result<DispatchAction, RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    let protocol_version = session.protocol_version();
    let data = session.data_connector();
    run_restored_with_dispatcher(
        session.client_mut(),
        options,
        protocol_version,
        dispatch,
        send_system_image,
        move |port, response| {
            let data = data.clone();
            async move {
                data.send(port, &response).await?;
                Ok(())
            }
        },
        progress,
    )
    .await
}

pub async fn run_restored<S, F, Fut, P>(
    client: &mut RestoredClient<S>,
    options: &RestoreOptions,
    protocol_version: u64,
    prepared: &PreparedRestoreData,
    send_system_image: F,
    progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Option<u16>) -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    let dispatch = |request: DataRequest| {
        std::future::ready(prepared.dispatch(&request).map_err(RestoreRunError::from))
    };
    run_restored_with_dispatcher(
        client,
        options,
        protocol_version,
        dispatch,
        send_system_image,
        |_port, _response| async { Err(RestoreRunError::DataPortNotConfigured) },
        progress,
    )
    .await
}

pub async fn run_restored_with_data_ports<S, F, Fut, D, DFut, P>(
    client: &mut RestoredClient<S>,
    options: &RestoreOptions,
    protocol_version: u64,
    prepared: &PreparedRestoreData,
    send_system_image: F,
    send_data_response: D,
    progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Option<u16>) -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    D: FnMut(u16, Dictionary) -> DFut,
    DFut: Future<Output = Result<(), RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    let dispatch = |request: DataRequest| {
        std::future::ready(prepared.dispatch(&request).map_err(RestoreRunError::from))
    };
    run_restored_with_dispatcher(
        client,
        options,
        protocol_version,
        dispatch,
        send_system_image,
        send_data_response,
        progress,
    )
    .await
}

pub async fn run_restored_with_dispatcher<S, F, Fut, D, DFut, R, RFut, P>(
    client: &mut RestoredClient<S>,
    options: &RestoreOptions,
    protocol_version: u64,
    mut dispatch: R,
    mut send_system_image: F,
    mut send_data_response: D,
    mut progress: P,
) -> Result<RestoreOutcome, RestoreRunError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Option<u16>) -> Fut,
    Fut: Future<Output = Result<(), RestoreRunError>>,
    D: FnMut(u16, Dictionary) -> DFut,
    DFut: Future<Output = Result<(), RestoreRunError>>,
    R: FnMut(DataRequest) -> RFut,
    RFut: Future<Output = Result<DispatchAction, RestoreRunError>>,
    P: FnMut(RestoreProgress),
{
    client
        .start_restore(options.to_dictionary(), protocol_version)
        .await?;

    loop {
        match client.next_message().await? {
            RestoredMessage::DataRequest(request) => {
                let data_port = request.data_port();
                match dispatch(request).await? {
                    DispatchAction::SystemImage => send_system_image(data_port).await?,
                    DispatchAction::Send(response) => {
                        if let Some(port) = data_port {
                            send_data_response(port, response).await?;
                        } else {
                            client.send(&response).await?;
                        }
                    }
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
                    Some(0) => {
                        let mut acknowledgement = Dictionary::new();
                        acknowledgement.insert("MsgType".into(), "ReceivedFinalStatusMsg".into());
                        client.send(&acknowledgement).await?;
                        return Ok(RestoreOutcome);
                    }
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
            RestoredMessage::Checkpoint(checkpoint) => {
                if let Some(error) = checkpoint.error() {
                    warn!(
                        checkpoint = checkpoint.identifier(),
                        result = checkpoint.result(),
                        error,
                        "restore checkpoint reported an error"
                    );
                } else if let Some(warning) = checkpoint.warning() {
                    warn!(
                        checkpoint = checkpoint.identifier(),
                        result = checkpoint.result(),
                        warning,
                        "restore checkpoint reported a warning"
                    );
                } else {
                    debug!(
                        checkpoint = checkpoint.identifier(),
                        name = checkpoint.name(),
                        complete = checkpoint.complete(),
                        result = checkpoint.result(),
                        "restore checkpoint updated"
                    );
                }
            }
            RestoredMessage::RestoreAttestation(_) => {
                let mut response = Dictionary::new();
                response.insert("RestoreShouldAttest".into(), false.into());
                client.send(&response).await?;
            }
            RestoredMessage::RestoredCrash(message) => {
                warn!(keys = message.len(), "restored reported a crash")
            }
            RestoredMessage::AsyncWait(message) => {
                debug!(keys = message.len(), "restored requested an async wait")
            }
            RestoredMessage::RestoreProtocol(message) => {
                debug!(keys = message.len(), "received restore protocol metadata")
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
    #[error(transparent)]
    Connect(#[from] RestoredConnectError),
    #[error(transparent)]
    Asr(#[from] AsrError),
    #[error("restore data provider failed")]
    DataProvider(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("restore failed with AMR error {0}")]
    Amr(u64),
    #[error("restore failed with device status {0}")]
    DeviceStatus(u64),
    #[error("device rejected baseband data")]
    BasebandRejected,
    #[error("system image transfer failed: {0}")]
    SystemImage(String),
    #[error("restored requested a separate data port without a configured connector")]
    DataPortNotConfigured,
}

impl RestoreRunError {
    pub fn data_provider(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::DataProvider(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

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

            let mut attestation = Dictionary::new();
            attestation.insert("MsgType".into(), "RestoreAttestation".into());
            framed.send(&attestation).await.unwrap();
            let attestation = framed.receive().await.unwrap();
            assert_eq!(
                attestation
                    .get("RestoreShouldAttest")
                    .and_then(Value::as_boolean),
                Some(false)
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
            let acknowledgement = framed.receive().await.unwrap();
            assert_eq!(
                acknowledgement.get("MsgType").and_then(Value::as_string),
                Some("ReceivedFinalStatusMsg")
            );
        });

        let prepared = PreparedRestoreData::default().with_root_ticket(vec![1, 2, 3]);
        let result = run_restored(
            &mut client,
            &RestoreOptions::erase(),
            15,
            &prepared,
            |_| async { Ok(()) },
            |_| {},
        )
        .await;
        server.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn routes_responses_to_requested_data_port() {
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let mut client = RestoredClient::new(client_stream, "test");
        let server = tokio::spawn(async move {
            let mut framed = PlistFramed::new(server_stream);
            framed.receive().await.unwrap();
            let mut request = Dictionary::new();
            request.insert("MsgType".into(), "DataRequestMsg".into());
            request.insert("DataType".into(), "RootTicket".into());
            request.insert("DataPort".into(), 2345_u64.into());
            framed.send(&request).await.unwrap();

            let mut status = Dictionary::new();
            status.insert("MsgType".into(), "StatusMsg".into());
            status.insert("Status".into(), 0_u64.into());
            framed.send(&status).await.unwrap();
            let acknowledgement = framed.receive().await.unwrap();
            assert_eq!(
                acknowledgement.get("MsgType").and_then(Value::as_string),
                Some("ReceivedFinalStatusMsg")
            );
        });
        let responses = Arc::new(Mutex::new(Vec::new()));
        let response_sink = responses.clone();
        let prepared = PreparedRestoreData::default().with_root_ticket(vec![1, 2, 3]);

        run_restored_with_data_ports(
            &mut client,
            &RestoreOptions::erase(),
            15,
            &prepared,
            |_| async { Ok(()) },
            move |port, response| {
                let response_sink = response_sink.clone();
                async move {
                    response_sink
                        .lock()
                        .expect("response mutex must remain available")
                        .push((port, response));
                    Ok(())
                }
            },
            |_| {},
        )
        .await
        .unwrap();
        server.await.unwrap();

        let responses = responses
            .lock()
            .expect("response mutex must remain available");
        assert_eq!(responses[0].0, 2345);
        assert!(responses[0].1.contains_key("RootTicketData"));
    }

    #[test]
    fn adapts_legacy_progress_operations() {
        assert_eq!(adapt_operation(36, 13), 37);
        assert_eq!(adapt_operation(36, 14), 36);
    }
}
