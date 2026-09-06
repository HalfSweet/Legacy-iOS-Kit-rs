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
        let inspection = device.inspect().await?;
        println!(
            "model={} os={} battery={:?} serial_readable={} jailbreak={:?} ssh={:?} issues={:?}",
            info.product_type(),
            info.product_version(),
            inspection.battery_percent(),
            inspection.serial_number().is_some(),
            inspection.jailbreak(),
            inspection.ssh_available(),
            inspection.issues()
        );
        if let Some(storage) = inspection.storage() {
            println!(
                "storage_bytes={} free_bytes={}",
                storage.total_bytes(),
                storage.free_bytes()
            );
        }
    }
    Ok(())
}
