# User application operations

`IpaPackage::open` inspects the actual IPA (XML or binary Info.plist), hashes the
file and retains that file handle. A caller must compare its digest and native
identity against its trusted distribution metadata before transferring it.
`InstalledApp::product_version` and `build_version` expose independent values;
`version` retains its older display fallback.

Use `NormalDevice::install_user_app` with `AppInstallMode::Install` for an absent
application, or `Upgrade` for an existing User application. System applications
and unknown application types are rejected. The API uses ordinary AFC and
installation_proxy; it does not require AFC2, change signing policy, install
AppSync or move apps into system directories. Upgrade submits the system's
Upgrade command and retains the application's data. Uninstall submits the
system's Uninstall command, which removes the application and its container;
the embedding application must obtain explicit user consent first.

Each request owns a new `AppOperationControl`. Cancellation can win until the
atomic submission transition; afterwards `cancel` refuses and the caller must
wait or reconcile. Upload cancellation is checked between bounded AFC exchanges.
Do not abort the containing task after submission. `before_commit` is the
fallible hook for durable intent recording. Progress callbacks should return
promptly and must not panic. The caller owns device exclusion and shutdown
protection for the operation's lifetime.

Uploads use unique `/PublicStaging/{uuid}.ipa` paths, rehash their input, retain
both device service connections, and bound service, transfer and installation
waits. Cleanup failure is separately reported by the outcome and progress event.
An uncertain submitted operation retains its staging file, since the device may
still be consuming it. `Error` alone or `ErrorDescription` alone terminates an
operation, with typed diagnostics that do not expose raw device descriptions.
`PercentComplete` never substitutes for terminal status.

A successful response means installation_proxy reported completion. The caller
must subsequently check registration, native version/build and its build receipt.
After disconnect, timeout or process interruption, perform read-only verification;
never automatically replay a write. The legacy `install_ipa` and `uninstall_app`
wrappers remain available with these User-only constraints and default timeouts.

Tests exercise protocol transcripts, malformed responses, interrupted AFC writes,
IPA inspection, atomic cancellation and cleanup decisions without device I/O.
Hardware behavior still requires explicit acceptance on the supported device.

`app_build_receipt` reads a bounded `build-receipt.json` through House Arrest from
the registered app's container. `installed_system_package_status` optionally
reads the dpkg status file through an existing AFC2 service, with a five-second
budget and four-MiB limit. Failure means the prerequisite could not be observed;
it does not prove that a package is absent. Neither method enables a service or
changes device contents. AFC reads use bounded frames and read-only file opens.
