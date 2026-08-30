use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, Weak},
};

use legacy_ios_core::DeviceSelector;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

#[derive(Clone, Default)]
pub(crate) struct DeviceLeaseRegistry {
    locks: Arc<Mutex<HashMap<DeviceSelector, Weak<AsyncMutex<()>>>>>,
}

impl DeviceLeaseRegistry {
    pub(crate) async fn acquire(&self, selector: DeviceSelector) -> DeviceLease {
        let lock = {
            let mut locks = self
                .locks
                .lock()
                .expect("device lease registry mutex must remain available");
            if let Some(lock) = locks.get(&selector).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                locks.insert(selector.clone(), Arc::downgrade(&lock));
                lock
            }
        };
        let guard = lock.lock_owned().await;
        DeviceLease {
            selector,
            _guard: guard,
        }
    }
}

impl fmt::Debug for DeviceLeaseRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DeviceLeaseRegistry").finish()
    }
}

pub struct DeviceLease {
    selector: DeviceSelector,
    _guard: OwnedMutexGuard<()>,
}

impl DeviceLease {
    pub fn selector(&self) -> &DeviceSelector {
        &self.selector
    }
}

impl fmt::Debug for DeviceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceLease")
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use legacy_ios_core::Ecid;

    use super::*;

    #[tokio::test]
    async fn serializes_leases_for_one_device() {
        let leases = DeviceLeaseRegistry::default();
        let selector = DeviceSelector::Ecid(Ecid::new(42));
        let first = leases.acquire(selector.clone()).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(10), leases.acquire(selector.clone()))
                .await
                .is_err()
        );
        drop(first);
        assert_eq!(leases.acquire(selector.clone()).await.selector(), &selector);
    }
}
