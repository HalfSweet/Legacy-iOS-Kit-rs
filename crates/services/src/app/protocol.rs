use plist::{Dictionary, Value};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    AppFailure, AppFilter, AppIdentifier, AppOperationObserver, AppProgress, AppRejection,
    InstalledApp,
};
use crate::{ServiceError, plist_service::PropertyListService};

pub(super) fn lookup_request(filter: AppFilter, ids: Option<&[AppIdentifier]>) -> Dictionary {
    let mut options = Dictionary::new();
    options.insert("ApplicationType".into(), filter.service_value().into());
    options.insert(
        "ReturnAttributes".into(),
        Value::Array(
            [
                "CFBundleIdentifier",
                "CFBundleDisplayName",
                "CFBundleName",
                "CFBundleShortVersionString",
                "CFBundleVersion",
                "ApplicationType",
                "Path",
            ]
            .into_iter()
            .map(Value::from)
            .collect(),
        ),
    );
    if let Some(ids) = ids {
        options.insert(
            "BundleIDs".into(),
            Value::Array(ids.iter().map(|id| Value::from(id.as_str())).collect()),
        );
    }
    let mut request = Dictionary::new();
    request.insert("Command".into(), "Lookup".into());
    request.insert("ClientOptions".into(), options.into());
    request
}

pub(super) fn rejection(response: &Dictionary) -> Result<(), ServiceError> {
    if response.contains_key("Error") || response.contains_key("ErrorDescription") {
        let reason = match response.get("Error").and_then(Value::as_string) {
            Some(
                "ApplicationVerificationFailed"
                | "SignatureVerificationFailed"
                | "MissingCodeSignature",
            ) => AppRejection::Signature,
            Some(
                "DeviceOSVersionTooLow" | "DeviceFamilyNotSupported" | "IncorrectArchitecture",
            ) => AppRejection::Compatibility,
            Some("ApplicationAlreadyInstalled") => AppRejection::AlreadyInstalled,
            Some("ApplicationNotFound") => AppRejection::NotFound,
            Some("InsufficientStorage" | "DiskFull") => AppRejection::Storage,
            Some("PackageExtractionFailed" | "PackageInspectionFailed" | "PackageMoveFailed") => {
                AppRejection::Package
            }
            _ => AppRejection::Other,
        };
        return Err(AppFailure::Rejected(reason).into());
    }
    Ok(())
}

pub(super) async fn read_lookup<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut PropertyListService<S>,
) -> Result<Vec<InstalledApp>, ServiceError> {
    loop {
        let mut response = client.receive().await?;
        rejection(&response)?;
        if let Some(result) = response.remove("LookupResult") {
            let apps = result
                .into_dictionary()
                .ok_or(AppFailure::InvalidResponse)?;
            let mut result = Vec::with_capacity(apps.len());
            for (bundle_id, value) in apps {
                AppIdentifier::parse(bundle_id.clone())?;
                let dictionary = value.into_dictionary().ok_or(AppFailure::InvalidResponse)?;
                if dictionary
                    .get("CFBundleIdentifier")
                    .is_some_and(|id| id.as_string() != Some(&bundle_id))
                {
                    return Err(AppFailure::InvalidResponse.into());
                }
                result.push(InstalledApp {
                    bundle_id,
                    name: string(&dictionary, "CFBundleDisplayName")
                        .or_else(|| string(&dictionary, "CFBundleName")),
                    version: string(&dictionary, "CFBundleShortVersionString"),
                    build_version: string(&dictionary, "CFBundleVersion"),
                    application_type: string(&dictionary, "ApplicationType"),
                    path: string(&dictionary, "Path"),
                });
            }
            result.sort_by(|left, right| left.bundle_id.cmp(&right.bundle_id));
            return Ok(result);
        }
        if response.get("Status").and_then(Value::as_string) == Some("Complete") {
            return Err(AppFailure::InvalidResponse.into());
        }
    }
}

pub(super) async fn wait_for_operation<S: AsyncRead + AsyncWrite + Unpin>(
    installer: &mut PropertyListService<S>,
    observer: &dyn AppOperationObserver,
) -> Result<(), ServiceError> {
    loop {
        let response = installer.receive().await?;
        rejection(&response)?;
        let percent = response
            .get("PercentComplete")
            .and_then(Value::as_unsigned_integer)
            .filter(|value| *value <= 100)
            .map(|value| value as u8);
        observer.progress(AppProgress::Device { percent });
        if response.get("Status").and_then(Value::as_string) == Some("Complete") {
            return Ok(());
        }
    }
}
fn string(dictionary: &Dictionary, key: &str) -> Option<String> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
}
