use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{DeviceMode, DeviceSnapshot};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(u128);

impl OperationId {
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:032x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionId(u64);

impl ActionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    InspectDevice,
    SaveShsh,
    Restore,
    BootRamdisk,
    JustBoot,
    Jailbreak,
    AppManagement,
    DataManagement,
    Utility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationPhase {
    Planning,
    Preflight,
    Downloading,
    Personalizing,
    WaitingForDevice,
    Exploiting,
    Booting,
    Restoring,
    TransferringFilesystem,
    FlashingFirmware,
    Verifying,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellationSafety {
    Immediate,
    AtCheckpoint,
    UnsafeUntilPhaseEnds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressUnit {
    Steps,
    Bytes,
    Percent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub phase: OperationPhase,
    pub completed: u64,
    pub total: Option<u64>,
    pub unit: ProgressUnit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ActionKind {
    FollowDfuInstructions {
        steps: Vec<String>,
    },
    TrustDevice,
    ReconnectDevice,
    /// The user must run the jailbreak app the operation placed on the home
    /// screen (g1lbertJB's DemoApp remount step).
    RunJailbreakApp {
        name: String,
    },
    ProvideCredential {
        name: String,
    },
    UseExternalPwnHardware {
        family: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationOutcome {
    pub operation: OperationKind,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "event")]
pub enum OperationEvent {
    PhaseStarted {
        phase: OperationPhase,
        cancellation: CancellationSafety,
    },
    Progress(Progress),
    ModeChanged {
        mode: DeviceMode,
    },
    DeviceDisconnected,
    DeviceReconnected {
        device: DeviceSnapshot,
    },
    ActionRequired {
        id: ActionId,
        action: ActionKind,
    },
    Warning {
        message: String,
    },
    CancellationDeferred {
        phase: OperationPhase,
    },
    Completed {
        outcome: OperationOutcome,
    },
}
