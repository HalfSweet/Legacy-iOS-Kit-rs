use legacy_ios_core::DeviceMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbePolicy {
    Open,
    SystemManaged,
}

#[cfg(target_os = "macos")]
pub(crate) fn probe_policy(mode: DeviceMode, _info: &nusb::DeviceInfo) -> ProbePolicy {
    if mode == DeviceMode::Normal {
        ProbePolicy::SystemManaged
    } else {
        ProbePolicy::Open
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn probe_policy(mode: DeviceMode, info: &nusb::DeviceInfo) -> ProbePolicy {
    if mode == DeviceMode::Normal && !is_direct_usb_driver(info.driver()) {
        ProbePolicy::SystemManaged
    } else {
        ProbePolicy::Open
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn probe_policy(_mode: DeviceMode, _info: &nusb::DeviceInfo) -> ProbePolicy {
    ProbePolicy::Open
}

#[cfg(target_os = "windows")]
pub(crate) fn driver_name(info: &nusb::DeviceInfo) -> Option<String> {
    info.driver().map(ToOwned::to_owned)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn driver_name(_info: &nusb::DeviceInfo) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn is_direct_usb_driver(driver: Option<&str>) -> bool {
    driver.is_some_and(|driver| {
        let driver = driver.to_ascii_lowercase();
        driver.contains("winusb") || driver.contains("libusb")
    })
}
