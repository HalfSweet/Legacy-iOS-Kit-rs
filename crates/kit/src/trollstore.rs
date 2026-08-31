use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};

use crate::KitError;

/// Install TrollStore's persistence helper into the Tips app from an SSH
/// ramdisk, mirroring upstream's trollstore.sh. `helper` is the
/// `trollstorehelper` binary from TrollStore.tar and `persistence_helper` is
/// the PersistenceHelper_Embedded binary.
pub(crate) async fn install_trollstore(
    ssh: &RamdiskSsh,
    persistence_helper: &[u8],
    helper: &[u8],
) -> Result<(), KitError> {
    let mounted = ssh.execute("mount_filesystems").await?;
    if !mounted.success() {
        return Err(KitError::Ssh(SshError::RemoteCommand(
            mounted.exit_status(),
        )));
    }
    let found = ssh
        .execute("find /mnt2/containers/Bundle/Application/ -name \"Tips.app\"")
        .await?;
    if !found.success() {
        return Err(KitError::Ssh(SshError::RemoteCommand(found.exit_status())));
    }
    let tips = String::from_utf8_lossy(found.stdout()).trim().to_owned();
    if tips.is_empty() {
        return Err(KitError::Ssh(SshError::Scp(
            "Tips.app was not found on the device".into(),
        )));
    }
    let path = |name: &str| {
        ScpPath::new(format!("{tips}/{name}"))
            .map_err(|error| KitError::Ssh(SshError::Scp(error.to_string())))
    };
    ssh.upload(&path("trollstorehelper")?, helper).await?;
    ssh.upload(&path("PersistenceHelper_Embedded")?, persistence_helper)
        .await?;
    let result = ssh
        .execute(&format!(
            "if [ ! -e {tips}/Tips_TROLLSTORE_BACKUP ]; then \
             mv {tips}/Tips {tips}/Tips_TROLLSTORE_BACKUP && \
             mv {tips}/PersistenceHelper_Embedded {tips}/Tips && \
             /usr/sbin/chown 33 {tips}/Tips && \
             chmod 755 {tips}/Tips {tips}/trollstorehelper && \
             /usr/sbin/chown 0 {tips}/trollstorehelper && \
             touch {tips}/.TrollStorePersistenceHelper; \
             fi"
        ))
        .await?;
    if !result.success() {
        return Err(KitError::Ssh(SshError::RemoteCommand(result.exit_status())));
    }
    Ok(())
}
