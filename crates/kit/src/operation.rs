use legacy_ios_core::OperationEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::KitError;

pub struct OperationHandle {
    events: mpsc::Receiver<Result<OperationEvent, KitError>>,
    cancellation: CancellationToken,
}

impl OperationHandle {
    pub(crate) fn channel(capacity: usize) -> (OperationEmitter, Self) {
        let (events, receiver) = mpsc::channel(capacity);
        let cancellation = CancellationToken::new();
        (
            OperationEmitter {
                events,
                cancellation: cancellation.clone(),
            },
            Self {
                events: receiver,
                cancellation,
            },
        )
    }

    pub async fn next_event(&mut self) -> Option<Result<OperationEvent, KitError>> {
        self.events.recv().await
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

pub(crate) struct OperationEmitter {
    events: mpsc::Sender<Result<OperationEvent, KitError>>,
    cancellation: CancellationToken,
}

impl OperationEmitter {
    pub(crate) async fn emit(&self, event: OperationEvent) -> bool {
        self.events.send(Ok(event)).await.is_ok()
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use legacy_ios_core::{CancellationSafety, OperationPhase};

    use super::*;

    #[tokio::test]
    async fn delivers_events_and_cancellation() {
        let (emitter, mut handle) = OperationHandle::channel(2);
        emitter
            .emit(OperationEvent::PhaseStarted {
                phase: OperationPhase::Preflight,
                cancellation: CancellationSafety::Immediate,
            })
            .await;

        assert!(handle.next_event().await.unwrap().is_ok());
        handle.cancel();
        assert!(emitter.is_cancelled());
    }
}
