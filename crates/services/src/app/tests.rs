use super::*;
use std::{io::Write, sync::Mutex};

fn app(kind: Option<&str>) -> InstalledApp {
    InstalledApp {
        bundle_id: "dev.example.app".into(),
        name: None,
        version: Some("1.2.0".into()),
        build_version: Some("42".into()),
        application_type: kind.map(str::to_owned),
        path: None,
    }
}
#[test]
fn user_only_install_and_upgrade_require_matching_observation() {
    assert!(validate_install_state(None, AppInstallMode::Install).is_ok());
    assert!(matches!(
        validate_install_state(None, AppInstallMode::Upgrade),
        Err(ServiceError::Application(AppFailure::NotInstalled))
    ));
    assert!(matches!(
        validate_install_state(Some(&app(Some("User"))), AppInstallMode::Install),
        Err(ServiceError::Application(AppFailure::AlreadyInstalled))
    ));
    assert!(validate_install_state(Some(&app(Some("User"))), AppInstallMode::Upgrade).is_ok());
    assert!(matches!(
        validate_install_state(Some(&app(Some("System"))), AppInstallMode::Upgrade),
        Err(ServiceError::Application(AppFailure::SystemApplication))
    ));
    assert!(matches!(
        validate_install_state(Some(&app(None)), AppInstallMode::Upgrade),
        Err(ServiceError::Application(
            AppFailure::UnknownApplicationType
        ))
    ));
}
#[test]
fn cancellation_and_commit_have_one_winner() {
    for _ in 0..100 {
        let control = AppOperationControl::default();
        let guard = control.claim().unwrap();
        let (cancel, commit) = std::thread::scope(|scope| {
            let cancel = scope.spawn(|| control.cancel());
            let commit = scope.spawn(|| control.commit());
            (cancel.join().unwrap(), commit.join().unwrap())
        });
        assert_ne!(cancel.is_ok(), commit.is_ok());
        assert_eq!(control.has_committed(), commit.is_ok());
        drop(guard);
        assert!(control.claim().is_err());
        if commit.is_ok() {
            assert!(control.has_committed());
            assert_eq!(control.cancel(), Err(AppCancelError::Finished));
        }
    }
}
#[tokio::test]
async fn queued_cancellation_is_observed_before_claiming() {
    let control = AppOperationControl::default();
    control.cancel().unwrap();
    control.cancelled().await;
    assert!(matches!(
        control.claim(),
        Err(ServiceError::Application(AppFailure::Cancelled))
    ));
}
async fn transcript(responses: Vec<Dictionary>) -> PropertyListService<tokio::io::DuplexStream> {
    let (host, device) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut peer = PropertyListService::new(device);
        for response in responses {
            peer.send(&response).await.unwrap();
        }
    });
    PropertyListService::new(host)
}
#[tokio::test]
async fn terminal_error_without_description_is_not_success() {
    let mut response = Dictionary::new();
    response.insert("Error".into(), "ApplicationVerificationFailed".into());
    response.insert("Status".into(), "Complete".into());
    let result = wait_for_operation(&mut transcript(vec![response]).await, &|_| {}).await;
    assert!(matches!(
        result,
        Err(ServiceError::Application(AppFailure::Rejected(
            AppRejection::Signature
        )))
    ));
    let mut response = Dictionary::new();
    response.insert(
        "ErrorDescription".into(),
        "sensitive device contents must not escape".into(),
    );
    let result = wait_for_operation(&mut transcript(vec![response]).await, &|_| {})
        .await
        .unwrap_err();
    assert!(!result.to_string().contains("sensitive"));
}
#[tokio::test]
async fn progress_does_not_replace_terminal_status_and_timeout_is_bounded() {
    let mut progress = Dictionary::new();
    progress.insert("PercentComplete".into(), 100u64.into());
    let mut complete = Dictionary::new();
    complete.insert("Status".into(), "Complete".into());
    let events = Mutex::new(Vec::new());
    wait_for_operation(&mut transcript(vec![progress, complete]).await, &|event| {
        events.lock().unwrap().push(event)
    })
    .await
    .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            AppProgress::Device { percent: Some(100) },
            AppProgress::Device { percent: None }
        ]
    );
    let (host, _device) = tokio::io::duplex(1024);
    let mut client = PropertyListService::new(host);
    let result = bounded(
        Duration::from_millis(5),
        AppPhase::Installation,
        wait_for_operation(&mut client, &|_| {}),
    )
    .await;
    assert!(matches!(
        result,
        Err(ServiceError::Application(AppFailure::TimedOut(
            AppPhase::Installation
        )))
    ));
}
#[tokio::test]
async fn lookup_preserves_native_versions_and_rejects_malformed_entries() {
    let ids = [AppIdentifier::parse("dev.example.app").unwrap()];
    let request = lookup_request(AppFilter::All, Some(&ids));
    let options = request["ClientOptions"].as_dictionary().unwrap();
    assert_eq!(
        options["BundleIDs"].as_array().unwrap()[0].as_string(),
        Some("dev.example.app")
    );
    let mut record = Dictionary::new();
    record.insert("CFBundleShortVersionString".into(), "1.2.0".into());
    record.insert("CFBundleVersion".into(), "42".into());
    let mut entries = Dictionary::new();
    entries.insert("dev.example.app".into(), record.into());
    let mut response = Dictionary::new();
    response.insert("LookupResult".into(), entries.clone().into());
    let result = read_lookup(&mut transcript(vec![response]).await)
        .await
        .unwrap();
    assert_eq!(result[0].product_version(), Some("1.2.0"));
    assert_eq!(result[0].build_version(), Some("42"));
    entries.insert("dev.example.app".into(), "invalid".into());
    let mut response = Dictionary::new();
    response.insert("LookupResult".into(), entries.into());
    assert!(matches!(
        read_lookup(&mut transcript(vec![response]).await).await,
        Err(ServiceError::Application(AppFailure::InvalidResponse))
    ));
}
fn ipa(path: &Path, binary: bool, executable: &str) {
    let mut archive = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    let mut info = Dictionary::new();
    for (key, value) in [
        ("CFBundleIdentifier", "dev.example.app"),
        ("CFBundleExecutable", executable),
        ("CFBundleShortVersionString", "1.2.0"),
        ("CFBundleVersion", "42"),
    ] {
        info.insert(key.into(), value.into());
    }
    let mut bytes = Vec::new();
    if binary {
        Value::Dictionary(info)
            .to_writer_binary(&mut bytes)
            .unwrap();
    } else {
        Value::Dictionary(info).to_writer_xml(&mut bytes).unwrap();
    }
    archive
        .start_file("Payload/Example.app/Info.plist", options)
        .unwrap();
    archive.write_all(&bytes).unwrap();
    archive
        .start_file("Payload/Example.app/Example", options)
        .unwrap();
    archive.write_all(b"binary").unwrap();
    archive.finish().unwrap();
}
#[tokio::test]
async fn package_inspection_reads_xml_and_binary_and_owns_the_verified_file() {
    let dir = tempfile::tempdir().unwrap();
    for binary in [true, false] {
        let path = dir.path().join("object-without-ipa-extension");
        ipa(&path, binary, "Example");
        let package = IpaPackage::open(&path).await.unwrap();
        assert_eq!(package.metadata().bundle_id().as_str(), "dev.example.app");
        assert_eq!(package.metadata().build_version(), Some("42"));
        assert_eq!(
            package.sha256(),
            &<[u8; 32]>::from(Sha256::digest(std::fs::read(&path).unwrap()))
        );
        std::fs::rename(&path, dir.path().join("previous")).unwrap();
        std::fs::write(&path, b"replaced").unwrap();
        let (mut file, _, _, size) = package.into_parts();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        assert_eq!(bytes.len() as u64, size);
    }
    let path = dir.path().join("bad.ipa");
    ipa(&path, true, "../Example");
    assert!(matches!(
        IpaPackage::open(path).await,
        Err(ServiceError::Application(AppFailure::InvalidPackage))
    ));
}

#[test]
fn uncertain_submission_retains_staging_until_reconciliation() {
    let timed_out = Err(ServiceError::Application(AppFailure::TimedOut(
        AppPhase::Installation,
    )));
    assert!(!cleanup_is_safe(true, &timed_out));
    assert!(cleanup_is_safe(false, &timed_out));
    assert!(cleanup_is_safe(true, &Ok(())));
    assert!(cleanup_is_safe(
        true,
        &Err(ServiceError::Application(AppFailure::Rejected(
            AppRejection::Signature
        )))
    ));
}

#[test]
fn receipt_path_stays_inside_the_registered_container() {
    let mut installed = app(Some("User"));
    installed.path = Some("/var/mobile/Applications/container/Example.app".into());
    assert_eq!(
        receipt_path(&installed).unwrap(),
        "/Example.app/build-receipt.json"
    );
    for invalid in ["/", "/.app", "/evil\0.app", "/evil\\path.app"] {
        installed.path = Some(invalid.into());
        assert!(receipt_path(&installed).is_err());
    }
}
