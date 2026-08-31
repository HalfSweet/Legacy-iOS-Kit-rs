use std::collections::VecDeque;
use std::time::Duration;

use legacy_ios_core::{DeviceMode, Ecid};
use legacy_ios_firmware::SigningTicket;
use legacy_ios_transport::{IbootClient, RecoveryError, UploadResult};
use sha2::Digest as _;
use thiserror::Error;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::{
    APTICKET, DEVICE_TREE, DestructiveConsent, ExploitPolicy, IBEC, IBSS, KERNEL, PlanId,
    PreparedBootComponent, RAMDISK, RamdiskBootPlan, TRUST_CACHE,
};

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RAMDISK_SETTLE: Duration = Duration::from_secs(2);

pub struct RamdiskBootPreparation {
    plan_id: PlanId,
    components: Vec<PreparedBootComponent>,
    boot_args: String,
    exploit_policy: ExploitPolicy,
}

impl RamdiskBootPreparation {
    pub fn new(
        plan: &RamdiskBootPlan,
        consent: &DestructiveConsent,
    ) -> Result<Self, RamdiskPreparationError> {
        if !plan.accepts(consent) {
            return Err(RamdiskPreparationError::ConsentMismatch);
        }
        let mut components = Vec::new();
        for pinned in plan.pinned() {
            let data = std::fs::read(pinned.path()).map_err(|source| {
                RamdiskPreparationError::ComponentRead {
                    name: pinned.name().to_owned(),
                    source,
                }
            })?;
            let digest = hex::encode(sha2::Sha256::digest(&data));
            if data.len() as u64 != pinned.size() || digest != pinned.sha256() {
                return Err(RamdiskPreparationError::ComponentChanged(
                    pinned.name().to_owned(),
                ));
            }
            let data = if pinned.name() == APTICKET {
                ticket_payload(&data)?
            } else {
                data
            };
            components.push(PreparedBootComponent::new(pinned.name(), data));
        }
        Ok(Self {
            plan_id: plan.id().clone(),
            components,
            boot_args: plan.boot_args().to_owned(),
            exploit_policy: plan.exploit_policy(),
        })
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub const fn exploit_policy(&self) -> ExploitPolicy {
        self.exploit_policy
    }

    fn find(&self, name: &str) -> Option<&PreparedBootComponent> {
        self.components
            .iter()
            .find(|component| component.name() == name)
    }
}

fn ticket_payload(data: &[u8]) -> Result<Vec<u8>, RamdiskPreparationError> {
    let ticket = SigningTicket::from_reader(std::io::Cursor::new(data))?;
    Ok(ticket.root_ticket().to_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamdiskBootOutcome;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamdiskBootProgress {
    SendingComponent { name: &'static str, bytes: u64 },
    WaitingForReconnect,
    Reconnected { mode: DeviceMode },
}

pub async fn boot_ramdisk(
    preparation: &RamdiskBootPreparation,
    ecid: Ecid,
    progress: &mut (dyn FnMut(RamdiskBootProgress) + Send),
) -> Result<RamdiskBootOutcome, RamdiskBootError> {
    let mut chain = RamdiskBootChain::new(
        preparation.find(IBEC).is_some(),
        preparation.find(APTICKET).is_some(),
        preparation.find(TRUST_CACHE).is_some(),
        preparation.boot_args.clone(),
    );
    let mut client = wait_for_device(ecid, progress).await?;
    if matches!(
        preparation.exploit_policy(),
        ExploitPolicy::Auto | ExploitPolicy::AlreadyPwned
    ) && client.device_info().pwned().is_none()
    {
        return Err(RamdiskBootError::NotPwned);
    }
    loop {
        match chain.next(client.mode())? {
            RamdiskBootAction::UploadDfu(name) => {
                let data = component(preparation, name)?.data();
                progress(RamdiskBootProgress::SendingComponent {
                    name,
                    bytes: data.len() as u64,
                });
                client = match client.upload_image(data).await? {
                    UploadResult::Connected(client) => *client,
                    UploadResult::Reenumerating => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        progress(RamdiskBootProgress::WaitingForReconnect);
                        let client = wait_for_device(ecid, progress).await?;
                        progress(RamdiskBootProgress::Reconnected {
                            mode: client.mode(),
                        });
                        client
                    }
                };
            }
            RamdiskBootAction::UploadRecovery(name) => {
                let data = component(preparation, name)?.data();
                progress(RamdiskBootProgress::SendingComponent {
                    name,
                    bytes: data.len() as u64,
                });
                client.upload_payload(data).await?;
            }
            RamdiskBootAction::Command(command) => {
                debug!(%command, "sending iBoot command");
                client.send_command(&command).await?;
            }
            RamdiskBootAction::Settle(duration) => tokio::time::sleep(duration).await,
            RamdiskBootAction::Reconnect => {
                drop(client);
                progress(RamdiskBootProgress::WaitingForReconnect);
                client = wait_for_device(ecid, progress).await?;
                progress(RamdiskBootProgress::Reconnected {
                    mode: client.mode(),
                });
            }
            RamdiskBootAction::Booted => break,
        }
    }
    info!("ramdisk boot chain completed");
    Ok(RamdiskBootOutcome)
}

fn component<'a>(
    preparation: &'a RamdiskBootPreparation,
    name: &'static str,
) -> Result<&'a PreparedBootComponent, RamdiskBootError> {
    preparation
        .find(name)
        .ok_or(RamdiskBootError::MissingComponent(name))
}

async fn wait_for_device(
    ecid: Ecid,
    progress: &mut (dyn FnMut(RamdiskBootProgress) + Send),
) -> Result<IbootClient, RamdiskBootError> {
    let deadline = Instant::now() + RECONNECT_TIMEOUT;
    loop {
        match IbootClient::open(Some(ecid)).await {
            Ok(client) => return Ok(client),
            Err(RecoveryError::NoDevice) if Instant::now() < deadline => {
                progress(RamdiskBootProgress::WaitingForReconnect);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(RecoveryError::NoDevice) => return Err(RamdiskBootError::ReconnectTimeout),
            Err(error) => return Err(error.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RamdiskBootAction {
    UploadDfu(&'static str),
    UploadRecovery(&'static str),
    Command(String),
    Settle(Duration),
    Reconnect,
    Booted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainState {
    Start,
    SentIbssDfu,
    SentIbecDfu,
    SentIbecRecovery,
    SentGo,
    ReconnectAfterGo,
    RecoveryPhase,
    Done,
}

struct RamdiskBootChain {
    state: ChainState,
    has_ibec: bool,
    pending: VecDeque<RamdiskBootAction>,
}

impl RamdiskBootChain {
    fn new(has_ibec: bool, has_ticket: bool, has_trust_cache: bool, boot_args: String) -> Self {
        let mut pending = VecDeque::new();
        if has_ticket {
            pending.push_back(RamdiskBootAction::UploadRecovery(APTICKET));
            pending.push_back(RamdiskBootAction::Command("ticket".into()));
        }
        pending.push_back(RamdiskBootAction::UploadRecovery(RAMDISK));
        pending.push_back(RamdiskBootAction::Command("getenv ramdisk-delay".into()));
        pending.push_back(RamdiskBootAction::Command("ramdisk".into()));
        pending.push_back(RamdiskBootAction::Settle(RAMDISK_SETTLE));
        pending.push_back(RamdiskBootAction::UploadRecovery(DEVICE_TREE));
        pending.push_back(RamdiskBootAction::Command("devicetree".into()));
        if has_trust_cache {
            pending.push_back(RamdiskBootAction::UploadRecovery(TRUST_CACHE));
            pending.push_back(RamdiskBootAction::Command("firmware".into()));
        }
        pending.push_back(RamdiskBootAction::UploadRecovery(KERNEL));
        pending.push_back(RamdiskBootAction::Command(format!(
            "setenv boot-args {boot_args}"
        )));
        pending.push_back(RamdiskBootAction::Command("bootx".into()));
        Self {
            state: ChainState::Start,
            has_ibec,
            pending,
        }
    }

    fn next(&mut self, mode: DeviceMode) -> Result<RamdiskBootAction, RamdiskBootError> {
        loop {
            match self.state {
                ChainState::Start => match mode {
                    DeviceMode::Dfu => {
                        self.state = ChainState::SentIbssDfu;
                        return Ok(RamdiskBootAction::UploadDfu(IBSS));
                    }
                    DeviceMode::Recovery => {
                        self.state = ChainState::SentIbecRecovery;
                    }
                    mode => return Err(RamdiskBootError::UnexpectedDfuOrRecovery(mode)),
                },
                ChainState::SentIbssDfu => match mode {
                    DeviceMode::Dfu => {
                        if !self.has_ibec {
                            return Err(RamdiskBootError::MissingComponent(IBEC));
                        }
                        self.state = ChainState::SentIbecDfu;
                        return Ok(RamdiskBootAction::UploadDfu(IBEC));
                    }
                    DeviceMode::Recovery => {
                        self.state = ChainState::SentIbecRecovery;
                    }
                    mode => return Err(RamdiskBootError::UnexpectedDfuOrRecovery(mode)),
                },
                ChainState::SentIbecDfu => match mode {
                    DeviceMode::Recovery => self.state = ChainState::RecoveryPhase,
                    mode => return Err(RamdiskBootError::ExpectedRecovery(mode)),
                },
                ChainState::SentIbecRecovery => {
                    if self.has_ibec {
                        self.state = ChainState::SentGo;
                        return Ok(RamdiskBootAction::UploadRecovery(IBEC));
                    }
                    self.state = ChainState::RecoveryPhase;
                }
                ChainState::SentGo => {
                    self.state = ChainState::ReconnectAfterGo;
                    return Ok(RamdiskBootAction::Command("go".into()));
                }
                ChainState::ReconnectAfterGo => {
                    self.state = ChainState::RecoveryPhase;
                    return Ok(RamdiskBootAction::Reconnect);
                }
                ChainState::RecoveryPhase => {
                    if mode != DeviceMode::Recovery {
                        return Err(RamdiskBootError::ExpectedRecovery(mode));
                    }
                    if let Some(action) = self.pending.pop_front() {
                        return Ok(action);
                    }
                    self.state = ChainState::Done;
                    return Ok(RamdiskBootAction::Booted);
                }
                ChainState::Done => return Ok(RamdiskBootAction::Booted),
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RamdiskBootError {
    #[error("ramdisk boot chain is missing {0}")]
    MissingComponent(&'static str),
    #[error("expected DFU or Recovery mode, found {0:?}")]
    UnexpectedDfuOrRecovery(DeviceMode),
    #[error("expected Recovery mode, found {0:?}")]
    ExpectedRecovery(DeviceMode),
    #[error("timed out waiting for the device to reconnect")]
    ReconnectTimeout,
    #[error("device is not in a verified pwned DFU state")]
    NotPwned,
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}

#[derive(Debug, Error)]
pub enum RamdiskPreparationError {
    #[error("destructive consent does not match the ramdisk boot plan")]
    ConsentMismatch,
    #[error("cannot read {name} component: {source}")]
    ComponentRead {
        name: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} changed after ramdisk boot planning; resolve a new plan")]
    ComponentChanged(String),
    #[error(transparent)]
    Ticket(#[from] legacy_ios_firmware::TicketError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(
        chain: &mut RamdiskBootChain,
        modes: &[DeviceMode],
    ) -> Result<Vec<RamdiskBootAction>, RamdiskBootError> {
        let mut actions = Vec::new();
        let mut modes = modes.iter().copied();
        let mut mode = modes.next().expect("at least one mode");
        loop {
            let action = chain.next(mode)?;
            if action == RamdiskBootAction::Booted {
                actions.push(action);
                return Ok(actions);
            }
            let reconnects = matches!(
                action,
                RamdiskBootAction::UploadDfu(_) | RamdiskBootAction::Reconnect
            );
            actions.push(action);
            if reconnects {
                mode = modes.next().expect("a mode after reconnection");
            }
        }
    }

    #[test]
    fn prefers_img4_root_ticket_when_ticket_contains_legacy_data() {
        let ticket = br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>APTicket</key><data>AQ==</data>
<key>ApImg4Ticket</key><data>Ag==</data>
</dict></plist>"#;

        assert_eq!(ticket_payload(ticket).unwrap(), [2]);
    }

    #[test]
    fn boots_64_bit_chain_from_dfu() {
        let mut chain = RamdiskBootChain::new(true, true, true, "rd=md0".into());

        let actions = drive(
            &mut chain,
            &[DeviceMode::Dfu, DeviceMode::Recovery, DeviceMode::Recovery],
        )
        .unwrap();

        assert_eq!(
            actions,
            vec![
                RamdiskBootAction::UploadDfu(IBSS),
                RamdiskBootAction::UploadRecovery(IBEC),
                RamdiskBootAction::Command("go".into()),
                RamdiskBootAction::Reconnect,
                RamdiskBootAction::UploadRecovery(APTICKET),
                RamdiskBootAction::Command("ticket".into()),
                RamdiskBootAction::UploadRecovery(RAMDISK),
                RamdiskBootAction::Command("getenv ramdisk-delay".into()),
                RamdiskBootAction::Command("ramdisk".into()),
                RamdiskBootAction::Settle(RAMDISK_SETTLE),
                RamdiskBootAction::UploadRecovery(DEVICE_TREE),
                RamdiskBootAction::Command("devicetree".into()),
                RamdiskBootAction::UploadRecovery(TRUST_CACHE),
                RamdiskBootAction::Command("firmware".into()),
                RamdiskBootAction::UploadRecovery(KERNEL),
                RamdiskBootAction::Command("setenv boot-args rd=md0".into()),
                RamdiskBootAction::Command("bootx".into()),
                RamdiskBootAction::Booted,
            ]
        );
    }

    #[test]
    fn boots_32_bit_chain_from_recovery() {
        let mut chain = RamdiskBootChain::new(false, false, false, "rd=md0 -v".into());

        let actions = drive(&mut chain, &[DeviceMode::Recovery]).unwrap();

        assert_eq!(
            actions,
            vec![
                RamdiskBootAction::UploadRecovery(RAMDISK),
                RamdiskBootAction::Command("getenv ramdisk-delay".into()),
                RamdiskBootAction::Command("ramdisk".into()),
                RamdiskBootAction::Settle(RAMDISK_SETTLE),
                RamdiskBootAction::UploadRecovery(DEVICE_TREE),
                RamdiskBootAction::Command("devicetree".into()),
                RamdiskBootAction::UploadRecovery(KERNEL),
                RamdiskBootAction::Command("setenv boot-args rd=md0 -v".into()),
                RamdiskBootAction::Command("bootx".into()),
                RamdiskBootAction::Booted,
            ]
        );
    }

    #[test]
    fn sends_ibec_over_dfu_when_device_stays_in_dfu() {
        let mut chain = RamdiskBootChain::new(true, false, false, "rd=md0".into());

        let actions = drive(
            &mut chain,
            &[DeviceMode::Dfu, DeviceMode::Dfu, DeviceMode::Recovery],
        )
        .unwrap();

        assert_eq!(actions[0], RamdiskBootAction::UploadDfu(IBSS));
        assert_eq!(actions[1], RamdiskBootAction::UploadDfu(IBEC));
        assert_eq!(actions[2], RamdiskBootAction::UploadRecovery(RAMDISK));
    }

    #[test]
    fn requires_ibec_when_device_stays_in_dfu() {
        let mut chain = RamdiskBootChain::new(false, false, false, "rd=md0".into());

        let error = drive(&mut chain, &[DeviceMode::Dfu, DeviceMode::Dfu]).unwrap_err();

        assert!(matches!(error, RamdiskBootError::MissingComponent(IBEC)));
    }

    #[test]
    fn rejects_unexpected_mode_after_go() {
        let mut chain = RamdiskBootChain::new(true, false, false, "rd=md0".into());

        let error = drive(&mut chain, &[DeviceMode::Recovery, DeviceMode::Dfu]).unwrap_err();

        assert!(matches!(
            error,
            RamdiskBootError::ExpectedRecovery(DeviceMode::Dfu)
        ));
    }

    #[test]
    fn sends_go_before_reconnecting_recovery_ibec() {
        let mut chain = RamdiskBootChain::new(true, false, false, "rd=md0".into());

        let actions = drive(&mut chain, &[DeviceMode::Recovery, DeviceMode::Recovery]).unwrap();

        assert_eq!(actions[0], RamdiskBootAction::UploadRecovery(IBEC));
        assert_eq!(actions[1], RamdiskBootAction::Command("go".into()));
        assert_eq!(actions[2], RamdiskBootAction::Reconnect);
    }

    #[test]
    fn rejects_normal_mode_entry() {
        let mut chain = RamdiskBootChain::new(false, false, false, "rd=md0".into());

        let error = drive(&mut chain, &[DeviceMode::Normal]).unwrap_err();

        assert!(matches!(
            error,
            RamdiskBootError::UnexpectedDfuOrRecovery(DeviceMode::Normal)
        ));
    }
}
