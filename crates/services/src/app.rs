use std::{future::Future, path::Path, time::Duration};

use idevice::services::{
    house_arrest::HouseArrestClient, springboardservices::SpringBoardServicesClient,
};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

use crate::{DeviceFiles, NormalDevice, ServiceError, plist_service::PropertyListService};
mod control;
mod error;
mod package;
mod protocol;
mod staging;
pub use control::*;
pub use error::*;
pub use package::*;
use protocol::{lookup_request, read_lookup, wait_for_operation};
use staging::StagingClient;

const INSTALLATION_PROXY: &str = "com.apple.mobile.installation_proxy";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppFilter {
    User,
    System,
    All,
}
impl AppFilter {
    const fn service_value(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::System => "System",
            Self::All => "Any",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstalledApp {
    bundle_id: String,
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    build_version: Option<String>,
    application_type: Option<String>,
    #[serde(default)]
    path: Option<String>,
}
impl InstalledApp {
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    /// Legacy display accessor. Prefer the separate product/build accessors when comparing versions.
    pub fn version(&self) -> Option<&str> {
        self.product_version().or(self.build_version())
    }
    pub fn product_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub fn build_version(&self) -> Option<&str> {
        self.build_version.as_deref()
    }
    pub fn application_type(&self) -> Option<&str> {
        self.application_type.as_deref()
    }
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
    fn require_user(&self) -> Result<(), ServiceError> {
        match self.application_type() {
            Some("User") => Ok(()),
            Some("System") => Err(AppFailure::SystemApplication.into()),
            _ => Err(AppFailure::UnknownApplicationType.into()),
        }
    }
}
impl NormalDevice {
    pub async fn list_apps(&self, filter: AppFilter) -> Result<Vec<InstalledApp>, ServiceError> {
        self.query_apps(filter, None, AppOperationTimeouts::default().service)
            .await
    }
    /// Restricts Lookup on the device. An empty list never enumerates applications.
    pub async fn lookup_apps(
        &self,
        filter: AppFilter,
        ids: &[AppIdentifier],
    ) -> Result<Vec<InstalledApp>, ServiceError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.query_apps(filter, Some(ids), AppOperationTimeouts::default().service)
            .await
    }
    async fn query_apps(
        &self,
        filter: AppFilter,
        ids: Option<&[AppIdentifier]>,
        timeout: Duration,
    ) -> Result<Vec<InstalledApp>, ServiceError> {
        bounded(timeout, AppPhase::Lookup, async {
            let stream = self.connect_service(INSTALLATION_PROXY).await?;
            let mut client = PropertyListService::new(stream);
            client.send(&lookup_request(filter, ids)).await?;
            let result = read_lookup(&mut client).await?;
            if ids.is_some_and(|ids| {
                result
                    .iter()
                    .any(|app| !ids.iter().any(|id| id.as_str() == app.bundle_id()))
            }) {
                return Err(AppFailure::InvalidResponse.into());
            }
            Ok(result)
        })
        .await
    }
    /// Compatibility entry point; only User applications are accepted.
    pub async fn install_ipa(&self, ipa: &Path) -> Result<(), ServiceError> {
        let package = IpaPackage::open(ipa).await?;
        let apps = self
            .lookup_apps(
                AppFilter::All,
                std::slice::from_ref(package.metadata().bundle_id()),
            )
            .await?;
        let mode = if apps.is_empty() {
            AppInstallMode::Install
        } else {
            AppInstallMode::Upgrade
        };
        self.install_user_app(
            package,
            mode,
            &AppOperationControl::default(),
            &|_| {},
            AppOperationTimeouts::default(),
        )
        .await?;
        Ok(())
    }
    pub async fn install_user_app(
        &self,
        package: IpaPackage,
        mode: AppInstallMode,
        control: &AppOperationControl,
        observer: &dyn AppOperationObserver,
        timeouts: AppOperationTimeouts,
    ) -> Result<AppInstallOutcome, ServiceError> {
        let _guard = control.claim()?;
        let existing = self
            .query_apps(
                AppFilter::All,
                Some(std::slice::from_ref(package.metadata().bundle_id())),
                timeouts.service,
            )
            .await?;
        validate_install_state(existing.first(), mode)?;
        check_cancelled(control)?;
        // Open both services on this session before any upload; never reconnect
        // installation_proxy after staging onto a potentially different session.
        let stream = bounded(
            timeouts.service,
            AppPhase::Service,
            self.connect_service("com.apple.afc"),
        )
        .await?;
        let mut afc = StagingClient::new(stream);
        let stream = bounded(
            timeouts.service,
            AppPhase::Service,
            self.connect_service(INSTALLATION_PROXY),
        )
        .await?;
        let mut installer = PropertyListService::new(stream);
        bounded(timeouts.service, AppPhase::Transfer, afc.create_directory()).await?;
        check_cancelled(control)?;
        let device_path = format!("/PublicStaging/{}.ipa", uuid::Uuid::new_v4());
        observer.progress(AppProgress::Staging {
            path: device_path.clone(),
        });
        let mut clean_transport = false;
        let uploaded: Result<(), ServiceError> = async {
            let (file, _, expected, total) = package.into_parts();
            let mut local = tokio::fs::File::from_std(file);
            let fd = bounded(
                timeouts.transfer_idle,
                AppPhase::Transfer,
                afc.open(&device_path),
            )
            .await?;
            let mut digest = Sha256::new();
            let mut buffer = vec![0; 64 * 1024];
            let mut bytes = 0u64;
            let transfer = loop {
                if control.is_cancelled() {
                    break Err(AppFailure::Cancelled.into());
                }
                let count = bounded(timeouts.transfer_idle, AppPhase::Transfer, async {
                    Ok(local.read(&mut buffer).await?)
                })
                .await?;
                if count == 0 {
                    break if bytes == total && <[u8; 32]>::from(digest.finalize()) == expected {
                        Ok(())
                    } else {
                        Err(AppFailure::DigestMismatch.into())
                    };
                }
                if bytes + count as u64 > total {
                    break Err(AppFailure::DigestMismatch.into());
                }
                bounded(
                    timeouts.transfer_idle,
                    AppPhase::Transfer,
                    afc.write(fd, &buffer[..count]),
                )
                .await?;
                digest.update(&buffer[..count]);
                bytes += count as u64;
                observer.progress(AppProgress::Transfer { bytes, total });
            };
            bounded(timeouts.transfer_idle, AppPhase::Transfer, afc.close(fd)).await?;
            clean_transport = true;
            transfer
        }
        .await;
        let result = async {
            uploaded?;
            check_cancelled(control)?;
            observer.before_commit()?;
            control.commit()?;
            observer.progress(AppProgress::Committing);
            let mut request = Dictionary::new();
            request.insert("Command".into(), mode.command().into());
            request.insert("ClientOptions".into(), Dictionary::new().into());
            request.insert("PackagePath".into(), device_path.clone().into());
            bounded(timeouts.operation, AppPhase::Installation, async {
                installer.send(&request).await?;
                wait_for_operation(&mut installer, observer).await
            })
            .await
        }
        .await;
        // A timed-out AFC exchange may leave framing uncertain. Do not issue
        // another request on that connection; report the owned path for cleanup.
        let cleanup = if clean_transport && cleanup_is_safe(control.has_committed(), &result) {
            matches!(
                tokio::time::timeout(timeouts.cleanup, afc.remove(&device_path)).await,
                Ok(Ok(()))
            )
        } else {
            false
        };
        observer.progress(AppProgress::Cleanup { complete: cleanup });
        if !cleanup {
            warn!("application staging cleanup was not completed");
        }
        result?;
        info!("User application installation completed");
        Ok(AppInstallOutcome {
            staging_cleanup_complete: cleanup,
            staging_path: device_path,
        })
    }
    pub async fn uninstall_app(&self, bundle_id: &str) -> Result<(), ServiceError> {
        self.uninstall_user_app(
            &AppIdentifier::parse(bundle_id)?,
            &AppOperationControl::default(),
            &|_| {},
            AppOperationTimeouts::default(),
        )
        .await
    }
    pub async fn uninstall_user_app(
        &self,
        bundle_id: &AppIdentifier,
        control: &AppOperationControl,
        observer: &dyn AppOperationObserver,
        timeouts: AppOperationTimeouts,
    ) -> Result<(), ServiceError> {
        let _guard = control.claim()?;
        let existing = self
            .query_apps(
                AppFilter::All,
                Some(std::slice::from_ref(bundle_id)),
                timeouts.service,
            )
            .await?;
        existing
            .first()
            .ok_or(AppFailure::NotInstalled)?
            .require_user()?;
        check_cancelled(control)?;
        let stream = bounded(
            timeouts.service,
            AppPhase::Service,
            self.connect_service(INSTALLATION_PROXY),
        )
        .await?;
        let mut installer = PropertyListService::new(stream);
        observer.before_commit()?;
        control.commit()?;
        observer.progress(AppProgress::Committing);
        let mut request = Dictionary::new();
        request.insert("Command".into(), "Uninstall".into());
        request.insert("ClientOptions".into(), Dictionary::new().into());
        request.insert("ApplicationIdentifier".into(), bundle_id.as_str().into());
        bounded(timeouts.operation, AppPhase::Uninstallation, async {
            installer.send(&request).await?;
            wait_for_operation(&mut installer, observer).await
        })
        .await?;
        info!("User application uninstalled");
        Ok(())
    }
    /// Read the distribution receipt from the registered application's bundle
    /// using House Arrest. This never falls back to privileged services.
    pub async fn app_build_receipt(&self, app: &InstalledApp) -> Result<Vec<u8>, ServiceError> {
        let id = AppIdentifier::parse(app.bundle_id())?;
        let path = receipt_path(app)?;
        bounded(
            AppOperationTimeouts::default().service,
            AppPhase::Lookup,
            async {
                let stream = self
                    .connect_service("com.apple.mobile.house_arrest")
                    .await?;
                let mut service = PropertyListService::new(stream);
                let mut request = Dictionary::new();
                request.insert("Command".into(), "VendContainer".into());
                request.insert("Identifier".into(), id.as_str().into());
                service.send(&request).await?;
                let response = service.receive().await?;
                protocol::rejection(&response)?;
                if response.get("Status").and_then(Value::as_string) != Some("Complete") {
                    return Err(AppFailure::InvalidResponse.into());
                }
                StagingClient::new(service.into_inner())
                    .read_file(&path, 256 * 1024)
                    .await
            },
        )
        .await
    }
    /// Optional, read-only package-manager observation. Service unavailability
    /// means unknown prerequisites; AFC2 is never a hard installation dependency.
    pub async fn installed_system_package_status(&self) -> Result<Vec<u8>, ServiceError> {
        bounded(Duration::from_secs(5), AppPhase::Lookup, async {
            let stream = self.connect_service("com.apple.afc2").await?;
            StagingClient::new(stream)
                .read_file("/var/lib/dpkg/status", 4 * 1024 * 1024)
                .await
        })
        .await
    }
    pub async fn app_container(&self, bundle_id: &str) -> Result<DeviceFiles, ServiceError> {
        let client = self.service_client::<HouseArrestClient>().await?;
        Ok(DeviceFiles::new(
            client.vend_container(bundle_id.to_owned()).await?,
        ))
    }

    pub async fn app_documents(&self, bundle_id: &str) -> Result<DeviceFiles, ServiceError> {
        let client = self.service_client::<HouseArrestClient>().await?;
        Ok(DeviceFiles::new(
            client.vend_documents(bundle_id.to_owned()).await?,
        ))
    }

    pub async fn app_icon(&self, bundle_id: &str) -> Result<Vec<u8>, ServiceError> {
        let mut client = self.service_client::<SpringBoardServicesClient>().await?;
        Ok(client.get_icon_pngdata(bundle_id.to_owned()).await?)
    }

    pub async fn icon_state(&self) -> Result<Value, ServiceError> {
        let mut client = self.service_client::<SpringBoardServicesClient>().await?;
        Ok(client.get_icon_state(None).await?)
    }

    pub async fn set_icon_state(&self, state: Value) -> Result<(), ServiceError> {
        let mut client = self.service_client::<SpringBoardServicesClient>().await?;
        client.set_icon_state(state).await?;
        Ok(())
    }

    pub async fn refresh_icon_state(&self) -> Result<(), ServiceError> {
        let state = self.icon_state().await?;
        self.set_icon_state(state).await
    }
}

fn receipt_path(app: &InstalledApp) -> Result<String, ServiceError> {
    let path = app.path().ok_or(AppFailure::InvalidResponse)?;
    let name = path.rsplit('/').next().ok_or(AppFailure::InvalidResponse)?;
    if !name.ends_with(".app") || name.len() <= 4 || name.contains(['\0', '\\']) {
        return Err(AppFailure::InvalidResponse.into());
    }
    Ok(format!("/{name}/build-receipt.json"))
}
// A disconnected or timed-out installation may still be consuming its IPA.
// Retain staging until a caller has reconciled the device's actual state.
fn cleanup_is_safe(committed: bool, result: &Result<(), ServiceError>) -> bool {
    !committed
        || result.is_ok()
        || matches!(
            result,
            Err(ServiceError::Application(AppFailure::Rejected(_)))
        )
}
fn validate_install_state(
    existing: Option<&InstalledApp>,
    mode: AppInstallMode,
) -> Result<(), ServiceError> {
    if let Some(app) = existing {
        app.require_user()?;
    }
    match (existing, mode) {
        (Some(_), AppInstallMode::Install) => Err(AppFailure::AlreadyInstalled.into()),
        (None, AppInstallMode::Upgrade) => Err(AppFailure::NotInstalled.into()),
        _ => Ok(()),
    }
}
fn check_cancelled(control: &AppOperationControl) -> Result<(), ServiceError> {
    if control.is_cancelled() {
        Err(AppFailure::Cancelled.into())
    } else {
        Ok(())
    }
}
async fn bounded<T>(
    duration: Duration,
    phase: AppPhase,
    future: impl Future<Output = Result<T, ServiceError>>,
) -> Result<T, ServiceError> {
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| AppFailure::TimedOut(phase))?
}
#[cfg(test)]
mod tests;
