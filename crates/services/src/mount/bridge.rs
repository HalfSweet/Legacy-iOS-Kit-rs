//! Synchronous bridge over the async AFC client.
//!
//! FUSE callbacks are synchronous and run on driver-managed threads, while
//! `DeviceFiles` is async. The bridge owns the client on a dedicated worker
//! thread with a current-thread Tokio runtime; callbacks exchange requests
//! and replies over `std::sync::mpsc` channels. This keeps exactly one AFC
//! request in flight (the client requires `&mut self`) and avoids any
//! `block_on` re-entrancy hazards with the caller's runtime.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use tracing::{debug, warn};

use super::attr::{FsErrorKind, fs_error_kind};
use crate::{AfcPath, DeviceFileInfo, DeviceFiles, DeviceStorageInfo};

pub(crate) enum FsRequest {
    Info {
        path: AfcPath,
        reply: Sender<BridgeResult<DeviceFileInfo>>,
    },
    List {
        path: AfcPath,
        reply: Sender<BridgeResult<Vec<String>>>,
    },
    Storage {
        reply: Sender<BridgeResult<DeviceStorageInfo>>,
    },
    Read {
        path: AfcPath,
        offset: u64,
        len: usize,
        reply: Sender<BridgeResult<Vec<u8>>>,
    },
    Write {
        path: AfcPath,
        offset: u64,
        data: Vec<u8>,
        reply: Sender<BridgeResult<()>>,
    },
    CreateFile {
        path: AfcPath,
        reply: Sender<BridgeResult<()>>,
    },
    CreateDir {
        path: AfcPath,
        reply: Sender<BridgeResult<()>>,
    },
    Remove {
        path: AfcPath,
        reply: Sender<BridgeResult<()>>,
    },
    Rename {
        source: AfcPath,
        destination: AfcPath,
        reply: Sender<BridgeResult<()>>,
    },
}

pub(crate) type BridgeResult<T> = Result<T, FsErrorKind>;

/// Handle to the AFC worker thread. Dropping it stops the worker.
#[derive(Debug)]
pub(crate) struct AfcBridge {
    requests: Sender<FsRequest>,
    worker: Option<JoinHandle<()>>,
}

impl AfcBridge {
    pub(crate) fn spawn(files: DeviceFiles) -> std::io::Result<Self> {
        let (requests, rx) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("lik-afc-bridge".to_owned())
            .spawn(move || run_worker(files, rx))?;
        Ok(Self {
            requests,
            worker: Some(worker),
        })
    }

    fn send<T>(&self, build: impl FnOnce(Sender<BridgeResult<T>>) -> FsRequest) -> BridgeResult<T> {
        let (reply, reply_rx) = mpsc::channel();
        self.requests
            .send(build(reply))
            .map_err(|_| FsErrorKind::Io)?;
        reply_rx.recv().map_err(|_| FsErrorKind::Io)?
    }

    pub(crate) fn info(&self, path: AfcPath) -> BridgeResult<DeviceFileInfo> {
        self.send(|reply| FsRequest::Info { path, reply })
    }

    pub(crate) fn list(&self, path: AfcPath) -> BridgeResult<Vec<String>> {
        self.send(|reply| FsRequest::List { path, reply })
    }

    pub(crate) fn storage(&self) -> BridgeResult<DeviceStorageInfo> {
        self.send(|reply| FsRequest::Storage { reply })
    }

    pub(crate) fn read(&self, path: AfcPath, offset: u64, len: usize) -> BridgeResult<Vec<u8>> {
        self.send(|reply| FsRequest::Read {
            path,
            offset,
            len,
            reply,
        })
    }

    pub(crate) fn write(&self, path: AfcPath, offset: u64, data: Vec<u8>) -> BridgeResult<()> {
        self.send(|reply| FsRequest::Write {
            path,
            offset,
            data,
            reply,
        })
    }

    pub(crate) fn create_file(&self, path: AfcPath) -> BridgeResult<()> {
        self.send(|reply| FsRequest::CreateFile { path, reply })
    }

    pub(crate) fn create_dir(&self, path: AfcPath) -> BridgeResult<()> {
        self.send(|reply| FsRequest::CreateDir { path, reply })
    }

    pub(crate) fn remove(&self, path: AfcPath) -> BridgeResult<()> {
        self.send(|reply| FsRequest::Remove { path, reply })
    }

    pub(crate) fn rename(&self, source: AfcPath, destination: AfcPath) -> BridgeResult<()> {
        self.send(|reply| FsRequest::Rename {
            source,
            destination,
            reply,
        })
    }
}

impl Drop for AfcBridge {
    fn drop(&mut self) {
        // Closing the channel ends the worker loop; join it so the AFC client
        // is torn down deterministically before the mount guard is dropped.
        drop(std::mem::replace(&mut self.requests, mpsc::channel().0));
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            warn!("afc bridge worker panicked");
        }
    }
}

fn run_worker(mut files: DeviceFiles, rx: Receiver<FsRequest>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            warn!(%error, "failed to start afc bridge runtime");
            return;
        }
    };
    while let Ok(request) = rx.recv() {
        runtime.block_on(dispatch(&mut files, request));
    }
    debug!("afc bridge worker stopped");
}

async fn dispatch(files: &mut DeviceFiles, request: FsRequest) {
    match request {
        FsRequest::Info { path, reply } => {
            send(
                reply,
                files.info(&path).await.map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::List { path, reply } => {
            send(
                reply,
                files.list(&path).await.map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::Storage { reply } => {
            send(
                reply,
                files.storage_info().await.map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::Read {
            path,
            offset,
            len,
            reply,
        } => {
            send(
                reply,
                files
                    .read_at(&path, offset, len)
                    .await
                    .map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::Write {
            path,
            offset,
            data,
            reply,
        } => {
            send(
                reply,
                files
                    .write_at(&path, offset, &data)
                    .await
                    .map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::CreateFile { path, reply } => {
            send(
                reply,
                files
                    .create_file(&path)
                    .await
                    .map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::CreateDir { path, reply } => {
            send(
                reply,
                files.create_dir(&path).await.map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::Remove { path, reply } => {
            send(
                reply,
                files
                    .remove(&path, false)
                    .await
                    .map_err(|e| fs_error_kind(&e)),
            );
        }
        FsRequest::Rename {
            source,
            destination,
            reply,
        } => {
            send(
                reply,
                files
                    .rename(&source, &destination)
                    .await
                    .map_err(|e| fs_error_kind(&e)),
            );
        }
    }
}

fn send<T>(reply: Sender<BridgeResult<T>>, result: BridgeResult<T>) {
    // A send failure means the FUSE callback was abandoned (session teardown);
    // nothing actionable remains on this side.
    let _ = reply.send(result);
}
