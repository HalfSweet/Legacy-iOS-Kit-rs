use std::path::{Path, PathBuf};

use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{CancellationSafety, DeviceIdentity, DeviceSelector, Ecid, OperationPhase};
use legacy_ios_firmware::{SigningTicket, TicketError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{DestructiveConsent, ExploitPolicy, PlanId};

pub const IBSS: &str = "iBSS";
pub const IBEC: &str = "iBEC";
pub const RAMDISK: &str = "RestoreRamDisk";
pub const DEVICE_TREE: &str = "RestoreDeviceTree";
pub const TRUST_CACHE: &str = "RestoreTrustCache";
pub const KERNEL: &str = "RestoreKernelCache";
pub const APTICKET: &str = "ApTicket";

pub const DEFAULT_BOOT_ARGS: &str = "rd=md0";
const MAX_BOOT_ARGS_LEN: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RamdiskBootRequest {
    pub device: DeviceIdentity,
    pub ibss: PathBuf,
    pub ibec: Option<PathBuf>,
    pub ramdisk: PathBuf,
    pub device_tree: PathBuf,
    pub trust_cache: Option<PathBuf>,
    pub kernel: PathBuf,
    pub ticket: Option<PathBuf>,
    pub boot_args: Option<String>,
    pub exploit: ExploitPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RamdiskBootComponent {
    name: String,
    path: PathBuf,
    size: u64,
    sha256: String,
}

impl RamdiskBootComponent {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RamdiskBootPlanStep {
    pub kind: RamdiskBootStepKind,
    pub phase: OperationPhase,
    pub cancellation: CancellationSafety,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RamdiskBootStepKind {
    Preflight,
    AcquireDevice,
    Exploit,
    BootRamdisk,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RamdiskBootPlan {
    id: PlanId,
    device: DeviceIdentity,
    selector: DeviceSelector,
    ecid: Ecid,
    components: Vec<RamdiskBootComponent>,
    ticket: Option<RamdiskBootComponent>,
    boot_args: String,
    exploit: ExploitPolicy,
    steps: Vec<RamdiskBootPlanStep>,
}

impl RamdiskBootPlan {
    pub fn resolve(request: RamdiskBootRequest) -> Result<Self, RamdiskBootPlanError> {
        let ecid = request
            .device
            .ecid()
            .ok_or(RamdiskBootPlanError::MissingEcid)?;
        let selector = request
            .device
            .selector()
            .ok_or(RamdiskBootPlanError::MissingEcid)?;
        let profile = DeviceDatabase::bundled()
            .find_product(request.device.product_type())
            .ok_or_else(|| {
                RamdiskBootPlanError::UnknownDevice(request.device.product_type().clone())
            })?;
        let board_config = request
            .device
            .board_config()
            .ok_or(RamdiskBootPlanError::MissingBoardConfig)?;
        if !profile.board_configs().contains(board_config) {
            return Err(RamdiskBootPlanError::BoardConfigMismatch);
        }

        let mut components = vec![pin_component(IBSS, &request.ibss)?];
        if let Some(ibec) = &request.ibec {
            components.push(pin_component(IBEC, ibec)?);
        }
        components.push(pin_component(RAMDISK, &request.ramdisk)?);
        components.push(pin_component(DEVICE_TREE, &request.device_tree)?);
        if let Some(trust_cache) = &request.trust_cache {
            components.push(pin_component(TRUST_CACHE, trust_cache)?);
        }
        components.push(pin_component(KERNEL, &request.kernel)?);

        let ticket = request
            .ticket
            .as_ref()
            .map(|path| {
                let ticket = SigningTicket::open(path).map_err(|source| {
                    RamdiskBootPlanError::InvalidTicket {
                        path: path.clone(),
                        source,
                    }
                })?;
                ticket
                    .verify_ecid(ecid)
                    .map_err(|source| RamdiskBootPlanError::InvalidTicket {
                        path: path.clone(),
                        source,
                    })?;
                pin_component(APTICKET, path)
            })
            .transpose()?;

        let boot_args = request
            .boot_args
            .clone()
            .unwrap_or_else(|| DEFAULT_BOOT_ARGS.to_owned());
        if boot_args.is_empty()
            || boot_args.len() > MAX_BOOT_ARGS_LEN
            || boot_args.as_bytes().contains(&0)
        {
            return Err(RamdiskBootPlanError::InvalidBootArgs);
        }

        let steps = boot_steps(request.exploit);
        let id = plan_id(&request, &components, ticket.as_ref(), &boot_args);

        Ok(Self {
            id,
            device: request.device,
            selector,
            ecid,
            components,
            ticket,
            boot_args,
            exploit: request.exploit,
            steps,
        })
    }

    pub fn id(&self) -> &PlanId {
        &self.id
    }

    pub fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    pub fn selector(&self) -> &DeviceSelector {
        &self.selector
    }

    pub const fn ecid(&self) -> Ecid {
        self.ecid
    }

    pub fn components(&self) -> &[RamdiskBootComponent] {
        &self.components
    }

    pub fn ticket(&self) -> Option<&RamdiskBootComponent> {
        self.ticket.as_ref()
    }

    pub fn boot_args(&self) -> &str {
        &self.boot_args
    }

    pub const fn exploit_policy(&self) -> ExploitPolicy {
        self.exploit
    }

    pub fn steps(&self) -> &[RamdiskBootPlanStep] {
        &self.steps
    }

    pub(crate) fn pinned(&self) -> impl Iterator<Item = &RamdiskBootComponent> {
        self.components.iter().chain(self.ticket.iter())
    }

    pub fn confirm_destructive(&self) -> DestructiveConsent {
        DestructiveConsent {
            plan_id: self.id.clone(),
        }
    }

    pub fn accepts(&self, consent: &DestructiveConsent) -> bool {
        self.id == consent.plan_id
    }
}

fn pin_component(
    name: &'static str,
    path: &Path,
) -> Result<RamdiskBootComponent, RamdiskBootPlanError> {
    let data = std::fs::read(path).map_err(|source| RamdiskBootPlanError::ComponentRead {
        name,
        path: path.to_owned(),
        source,
    })?;
    Ok(RamdiskBootComponent {
        name: name.to_owned(),
        path: path.to_owned(),
        size: data.len() as u64,
        sha256: hex::encode(Sha256::digest(&data)),
    })
}

fn boot_steps(exploit: ExploitPolicy) -> Vec<RamdiskBootPlanStep> {
    let mut steps = vec![
        step(
            RamdiskBootStepKind::Preflight,
            OperationPhase::Preflight,
            CancellationSafety::Immediate,
        ),
        step(
            RamdiskBootStepKind::AcquireDevice,
            OperationPhase::WaitingForDevice,
            CancellationSafety::Immediate,
        ),
    ];
    if exploit != ExploitPolicy::None {
        steps.push(step(
            RamdiskBootStepKind::Exploit,
            OperationPhase::Exploiting,
            CancellationSafety::AtCheckpoint,
        ));
    }
    steps.push(step(
        RamdiskBootStepKind::BootRamdisk,
        OperationPhase::Booting,
        CancellationSafety::AtCheckpoint,
    ));
    steps
}

const fn step(
    kind: RamdiskBootStepKind,
    phase: OperationPhase,
    cancellation: CancellationSafety,
) -> RamdiskBootPlanStep {
    RamdiskBootPlanStep {
        kind,
        phase,
        cancellation,
    }
}

fn plan_id(
    request: &RamdiskBootRequest,
    components: &[RamdiskBootComponent],
    ticket: Option<&RamdiskBootComponent>,
    boot_args: &str,
) -> PlanId {
    let mut material = format!(
        "{}|{}|{:?}|{}",
        request.device.product_type(),
        request
            .device
            .board_config()
            .expect("resolved requests have a board config"),
        request.exploit,
        boot_args,
    );
    for component in components.iter().chain(ticket) {
        material.push_str(&format!(
            "|{}|{}|{}|{}",
            component.name,
            component.path.display(),
            component.size,
            component.sha256
        ));
    }
    PlanId(hex::encode(Sha256::digest(material.as_bytes())))
}

#[derive(Debug, Error)]
pub enum RamdiskBootPlanError {
    #[error("device identity has no ECID")]
    MissingEcid,
    #[error("device identity has no board config")]
    MissingBoardConfig,
    #[error("unknown device {0}")]
    UnknownDevice(legacy_ios_core::ProductType),
    #[error("board config does not belong to the selected product type")]
    BoardConfigMismatch,
    #[error("cannot read {name} component {}: {source}", path.display())]
    ComponentRead {
        name: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid signing ticket {}: {source}", path.display())]
    InvalidTicket {
        path: PathBuf,
        #[source]
        source: TicketError,
    },
    #[error("boot arguments are empty, contain NUL, or exceed {MAX_BOOT_ARGS_LEN} bytes")]
    InvalidBootArgs,
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::{BoardConfig, ProductType, Soc};
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn resolves_plan_and_binds_consent() {
        let components = ComponentFixture::new();
        let request = components.request(ExploitPolicy::AlreadyPwned);

        let plan = RamdiskBootPlan::resolve(request).unwrap();
        let consent = plan.confirm_destructive();

        assert!(plan.accepts(&consent));
        assert_eq!(plan.boot_args(), DEFAULT_BOOT_ARGS);
        assert_eq!(plan.components().len(), 5);
        assert_eq!(plan.components()[0].name(), IBSS);
        assert_eq!(plan.components()[0].size(), "ibss.img3".len() as u64);
        assert_eq!(
            plan.steps().last().map(|step| step.kind),
            Some(RamdiskBootStepKind::BootRamdisk)
        );
        assert!(
            plan.steps()
                .iter()
                .any(|step| step.kind == RamdiskBootStepKind::Exploit)
        );
    }

    #[test]
    fn omits_exploit_step_when_disabled() {
        let components = ComponentFixture::new();
        let plan = RamdiskBootPlan::resolve(components.request(ExploitPolicy::None)).unwrap();

        assert!(
            !plan
                .steps()
                .iter()
                .any(|step| step.kind == RamdiskBootStepKind::Exploit)
        );
    }

    #[test]
    fn rejects_missing_component() {
        let components = ComponentFixture::new();
        let mut request = components.request(ExploitPolicy::None);
        request.ramdisk = PathBuf::from("does-not-exist.img3");

        let error = RamdiskBootPlan::resolve(request).unwrap_err();

        assert!(matches!(
            error,
            RamdiskBootPlanError::ComponentRead { name: RAMDISK, .. }
        ));
    }

    #[test]
    fn rejects_invalid_boot_args() {
        let components = ComponentFixture::new();
        let mut request = components.request(ExploitPolicy::None);
        request.boot_args = Some("rd=md0\0malicious".to_owned());

        let error = RamdiskBootPlan::resolve(request).unwrap_err();

        assert!(matches!(error, RamdiskBootPlanError::InvalidBootArgs));
    }

    #[test]
    fn rejects_ticket_for_another_ecid() {
        let components = ComponentFixture::new();
        let ticket = NamedTempFile::new().unwrap();
        ticket
            .reopen()
            .unwrap()
            .write_all(
                br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>APTicket</key><data>AQID</data><key>ApECID</key><integer>43</integer>
</dict></plist>"#,
            )
            .unwrap();
        let mut request = components.request(ExploitPolicy::None);
        request.ticket = Some(ticket.path().to_owned());

        let error = RamdiskBootPlan::resolve(request).unwrap_err();

        assert!(matches!(error, RamdiskBootPlanError::InvalidTicket { .. }));
    }

    struct ComponentFixture {
        root: tempfile::TempDir,
    }

    impl ComponentFixture {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().unwrap(),
            }
        }

        fn request(&self, exploit: ExploitPolicy) -> RamdiskBootRequest {
            RamdiskBootRequest {
                device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                    .with_board_config(BoardConfig::from("n90"))
                    .with_ecid(Ecid::new(42)),
                ibss: self.write("ibss.img3"),
                ibec: Some(self.write("ibec.img3")),
                ramdisk: self.write("ramdisk.img3"),
                device_tree: self.write("devicetree.img3"),
                trust_cache: None,
                kernel: self.write("kernel.img3"),
                ticket: None,
                boot_args: None,
                exploit,
            }
        }

        fn write(&self, name: &str) -> PathBuf {
            let path = self.root.path().join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            path
        }
    }
}
