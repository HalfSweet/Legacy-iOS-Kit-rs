//! Opt-in hardware smoke test. Reads already-paired iPod touch 4 devices;
//! never pairs, authenticates to SSH, installs, or changes device mode.
use legacy_ios_services::{NormalBackend, NormalMux};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for device in NormalMux::new(NormalBackend::System).list_devices().await? {
        let info = device.query_info().await?;
        if info.product_type().as_str() != "iPod4,1" {
            continue;
        }
        let mut session = device.session().await?;
        let battery = session
            .get_value(
                Some("BatteryCurrentCapacity"),
                Some("com.apple.mobile.battery"),
            )
            .await?;
        let serial = session.get_value(Some("SerialNumber"), None).await?;
        session.close().await?;
        let storage = device.files().await?.storage_info().await?;
        println!(
            "model={} os={} battery={} serial_readable={} storage_bytes={} free_bytes={}",
            info.product_type(),
            info.product_version(),
            battery
                .as_unsigned_integer()
                .ok_or("battery value missing")?,
            serial.as_string().is_some_and(|value| !value.is_empty()),
            storage.total_bytes(),
            storage.free_bytes()
        );
    }
    Ok(())
}
