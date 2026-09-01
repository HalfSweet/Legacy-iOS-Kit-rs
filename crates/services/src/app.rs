use std::path::Path;

use idevice::{
    IdeviceService,
    services::{
        afc::{AfcClient, opcode::AfcFopenMode},
        house_arrest::HouseArrestClient,
        springboardservices::SpringBoardServicesClient,
    },
};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::{DeviceFiles, NormalDevice, ServiceError, plist_service::PropertyListService};

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

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn application_type(&self) -> Option<&str> {
        self.application_type.as_deref()
    }

    /// On-disk path of the app bundle reported by the installation proxy.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl NormalDevice {
    pub async fn list_apps(&self, filter: AppFilter) -> Result<Vec<InstalledApp>, ServiceError> {
        let stream = self.connect_service(INSTALLATION_PROXY).await?;
        let mut client = PropertyListService::new(stream);
        let mut options = Dictionary::new();
        options.insert("ApplicationType".into(), filter.service_value().into());
        let mut request = Dictionary::new();
        request.insert("Command".into(), "Lookup".into());
        request.insert("ClientOptions".into(), options.into());
        client.send(&request).await?;
        let mut response = client.receive().await?;
        let apps = response
            .remove("LookupResult")
            .and_then(Value::into_dictionary)
            .ok_or(ServiceError::UnexpectedValue("LookupResult"))?;
        let mut apps = apps
            .into_iter()
            .map(|(bundle_id, value)| {
                let dictionary = value.into_dictionary().unwrap_or_default();
                InstalledApp {
                    bundle_id,
                    name: string(&dictionary, "CFBundleDisplayName")
                        .or_else(|| string(&dictionary, "CFBundleName")),
                    version: string(&dictionary, "CFBundleShortVersionString")
                        .or_else(|| string(&dictionary, "CFBundleVersion")),
                    application_type: string(&dictionary, "ApplicationType"),
                    path: string(&dictionary, "Path"),
                }
            })
            .collect::<Vec<_>>();
        apps.sort_by(|left, right| left.bundle_id.cmp(&right.bundle_id));
        Ok(apps)
    }

    pub async fn install_ipa(&self, ipa: &Path) -> Result<(), ServiceError> {
        let file_name = ipa
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ServiceError::InvalidIpaPath)?;
        let device_path = format!("/PublicStaging/{file_name}");
        let mut local = tokio::fs::File::open(ipa).await?;
        let mut afc = AfcClient::connect(self.provider()).await?;
        let mut remote = afc.open(&device_path, AfcFopenMode::WrOnly).await?;
        let copied = tokio::io::copy(&mut local, &mut remote).await?;
        remote.shutdown().await?;
        remote.close().await?;
        info!(bytes = copied, "uploaded IPA to device staging");

        let stream = self.connect_service(INSTALLATION_PROXY).await?;
        let mut installer = PropertyListService::new(stream);
        let mut request = Dictionary::new();
        request.insert("Command".into(), "Install".into());
        request.insert("ClientOptions".into(), Dictionary::new().into());
        request.insert("PackagePath".into(), device_path.clone().into());
        installer.send(&request).await?;
        let installed = wait_for_operation(&mut installer, "install").await;
        let cleanup = afc.remove(&device_path).await;
        installed?;
        cleanup?;
        info!("installed IPA");
        Ok(())
    }

    pub async fn uninstall_app(&self, bundle_id: &str) -> Result<(), ServiceError> {
        let stream = self.connect_service(INSTALLATION_PROXY).await?;
        let mut installer = PropertyListService::new(stream);
        let mut request = Dictionary::new();
        request.insert("Command".into(), "Uninstall".into());
        request.insert("ClientOptions".into(), Dictionary::new().into());
        request.insert("ApplicationIdentifier".into(), bundle_id.into());
        installer.send(&request).await?;
        wait_for_operation(&mut installer, "uninstall").await?;
        info!(bundle_id, "uninstalled application");
        Ok(())
    }

    pub async fn app_container(&self, bundle_id: &str) -> Result<DeviceFiles, ServiceError> {
        let client = HouseArrestClient::connect(self.provider()).await?;
        Ok(DeviceFiles::new(
            client.vend_container(bundle_id.to_owned()).await?,
        ))
    }

    pub async fn app_documents(&self, bundle_id: &str) -> Result<DeviceFiles, ServiceError> {
        let client = HouseArrestClient::connect(self.provider()).await?;
        Ok(DeviceFiles::new(
            client.vend_documents(bundle_id.to_owned()).await?,
        ))
    }

    pub async fn app_icon(&self, bundle_id: &str) -> Result<Vec<u8>, ServiceError> {
        let mut client = SpringBoardServicesClient::connect(self.provider()).await?;
        Ok(client.get_icon_pngdata(bundle_id.to_owned()).await?)
    }

    pub async fn icon_state(&self) -> Result<Value, ServiceError> {
        let mut client = SpringBoardServicesClient::connect(self.provider()).await?;
        Ok(client.get_icon_state(None).await?)
    }

    pub async fn set_icon_state(&self, state: Value) -> Result<(), ServiceError> {
        let mut client = SpringBoardServicesClient::connect(self.provider()).await?;
        client.set_icon_state(state).await?;
        Ok(())
    }

    pub async fn refresh_icon_state(&self) -> Result<(), ServiceError> {
        let state = self.icon_state().await?;
        self.set_icon_state(state).await
    }
}

async fn wait_for_operation(
    installer: &mut PropertyListService<crate::RawServiceConnection>,
    operation: &'static str,
) -> Result<(), ServiceError> {
    loop {
        let mut response = installer.receive().await?;
        if let Some(error) = response
            .remove("ErrorDescription")
            .and_then(Value::into_string)
        {
            return Err(ServiceError::AppOperation { operation, error });
        }
        if let Some(percent) = response
            .get("PercentComplete")
            .and_then(Value::as_unsigned_integer)
        {
            debug!(percent, operation, "application operation progress");
        }
        if response.get("Status").and_then(Value::as_string) == Some("Complete") {
            return Ok(());
        }
    }
}

fn string(dictionary: &plist::Dictionary, key: &str) -> Option<String> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
}
