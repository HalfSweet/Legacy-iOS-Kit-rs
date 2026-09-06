use std::time::Duration;

use legacy_ios_core::{DeviceMode, Ecid};
use legacy_ios_transport::{IbootClient, PwnState, RecoveryError, UploadResult};
use thiserror::Error;
use tokio::time::Instant;
use tracing::info;

use crate::{ExploitPolicy, PreparedBootComponent, RestorePreparation, SepPayload};

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Restore boot stage 1: bring the device from DFU/pwned state through
/// iBSS/iBEC into verified Recovery mode and write the boot nonce. Returns
/// the live client so the runner can read the fresh device nonces for the
/// independent SEP signing (futurerestore.cpp:1613-1614) before stage 2.
pub async fn boot_to_recovery(
    preparation: &RestorePreparation,
    ecid: Ecid,
) -> Result<IbootClient, RestoreBootError> {
    let mut client = wait_for_device(ecid).await?;
    if matches!(
        preparation.exploit_policy(),
        ExploitPolicy::Auto | ExploitPolicy::AlreadyPwned
    ) && client.device_info().pwn_state(client.mode()) == PwnState::Stock
    {
        return Err(RestoreBootError::NotPwned);
    }
    if client.mode() == DeviceMode::Dfu
        && client.device_info().pwn_state(client.mode()) != PwnState::PatchedIbss
    {
        client = upload_dfu(client, component(preparation, "iBSS")?, ecid).await?;
    }

    if preparation.build_major() > 8 && client.mode() == DeviceMode::Dfu {
        client = upload_dfu(client, component(preparation, "iBEC")?, ecid).await?;
    } else if preparation.build_major() > 8
        && client.mode() == DeviceMode::Recovery
        && let Some(ibec) = find_component(preparation, "iBEC")
    {
        client.upload_payload(ibec.data()).await?;
        client.send_command("go").await?;
        drop(client);
        client = wait_for_mode(ecid, DeviceMode::Recovery).await?;
    }
    if client.mode() != DeviceMode::Recovery {
        return Err(RestoreBootError::ExpectedRecovery(client.mode()));
    }

    if let Some(nonce) = preparation.boot_nonce() {
        client
            .send_command(&format!("setenv com.apple.System.boot-nonce {nonce}"))
            .await?;
        client.send_command("saveenv").await?;
    }
    Ok(client)
}

/// Restore boot stage 2: on the recovery-mode client returned by
/// [`boot_to_recovery`], send the recovery ticket, logo, ramdisk, device
/// tree, the independently signed RestoreSEP payload (`rsepfirmware`), the
/// kernel, and `bootx`.
pub async fn boot_restore(
    mut client: IbootClient,
    preparation: &RestorePreparation,
    sep: Option<&SepPayload>,
) -> Result<RestoreBootOutcome, RestoreBootError> {
    if preparation.build_major() > 8
        && let Some(ticket) = preparation.recovery_ticket()
    {
        client.upload_payload(ticket).await?;
        client.send_command("ticket").await?;
    }
    client.send_command("setenv auto-boot false").await?;
    client.send_command("saveenv").await?;

    if let Some(image) = find_component(preparation, "RestoreLogo") {
        client.upload_payload(image.data()).await?;
        client.send_command("setpicture 4").await?;
        client.send_command("bgcolor 0 0 0").await?;
    }
    if let Some(image) = find_component(preparation, "RestoreRamDisk") {
        client.upload_payload(image.data()).await?;
        if client.device_info().effective_cpid() == 0x8900 {
            client.send_command("getenv ramdisk-delay").await?;
        }
        client.send_command("ramdisk").await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if let Some(image) = find_component(preparation, "RestoreDeviceTree") {
        client.upload_payload(image.data()).await?;
        client.send_command("devicetree").await?;
    }
    if preparation.send_rsep()
        && let Some(payload) = sep
    {
        client.upload_payload(payload.restore_sep()).await?;
        client.send_command("rsepfirmware").await?;
    }
    let kernel = component(preparation, "RestoreKernelCache")?;
    client.upload_payload(kernel.data()).await?;
    if preparation.build_major() >= 8 {
        client
            .send_command("setenv boot-args rd=md0 nand-enable-reformat=1 -progress")
            .await?;
    }
    client.send_command("bootx").await?;
    info!("restore boot chain started");
    Ok(RestoreBootOutcome)
}

async fn upload_dfu(
    client: IbootClient,
    component: &PreparedBootComponent,
    ecid: Ecid,
) -> Result<IbootClient, RestoreBootError> {
    match client.upload_image(component.data()).await? {
        UploadResult::Connected(client) => Ok(*client),
        UploadResult::Reenumerating => {
            tokio::time::sleep(Duration::from_millis(200)).await;
            wait_for_device(ecid).await
        }
    }
}

async fn wait_for_device(ecid: Ecid) -> Result<IbootClient, RestoreBootError> {
    let deadline = Instant::now() + RECONNECT_TIMEOUT;
    loop {
        match IbootClient::open(Some(ecid)).await {
            Ok(client) => return Ok(client),
            Err(RecoveryError::NoDevice) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(RecoveryError::NoDevice) => return Err(RestoreBootError::ReconnectTimeout),
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_mode(ecid: Ecid, mode: DeviceMode) -> Result<IbootClient, RestoreBootError> {
    let client = wait_for_device(ecid).await?;
    if client.mode() != mode {
        return Err(RestoreBootError::UnexpectedMode {
            expected: mode,
            actual: client.mode(),
        });
    }
    Ok(client)
}

fn component<'a>(
    preparation: &'a RestorePreparation,
    name: &'static str,
) -> Result<&'a PreparedBootComponent, RestoreBootError> {
    find_component(preparation, name).ok_or(RestoreBootError::MissingComponent(name))
}

fn find_component<'a>(
    preparation: &'a RestorePreparation,
    name: &str,
) -> Option<&'a PreparedBootComponent> {
    preparation
        .boot_components()
        .iter()
        .find(|component| component.name() == name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreBootOutcome;

#[derive(Debug, Error)]
pub enum RestoreBootError {
    #[error("restore boot chain is missing {0}")]
    MissingComponent(&'static str),
    #[error("expected Recovery mode after boot chain, found {0:?}")]
    ExpectedRecovery(DeviceMode),
    #[error("expected {expected:?} mode, found {actual:?}")]
    UnexpectedMode {
        expected: DeviceMode,
        actual: DeviceMode,
    },
    #[error("timed out waiting for the device to reconnect")]
    ReconnectTimeout,
    #[error("device is not in a verified pwned DFU state")]
    NotPwned,
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}
