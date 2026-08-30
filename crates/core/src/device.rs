use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::CoreError;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

string_id!(Udid);
string_id!(ProductType);
string_id!(BoardConfig);
string_id!(ConnectionId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ecid(u64);

impl Ecid {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Ecid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Ecid {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        };

        parsed
            .map(Self)
            .map_err(|_| CoreError::InvalidEcid(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceMode {
    Normal,
    Recovery,
    Dfu,
    Wtf,
    Restore,
    Ramdisk,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Soc {
    S5l8900,
    S5l8720,
    S5l8920,
    S5l8922,
    A4,
    A5,
    A5x,
    A6,
    A6x,
    A7,
    A8,
    A8x,
    A9,
    A9x,
    A10,
    A10x,
    A11,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Recovery,
    Dfu,
    PwnDfu,
    KDfu,
    Restore,
    TetheredRestore,
    OtaDowngrade,
    BlobRestore,
    OnboardShsh,
    SshRamdisk,
    Jailbreak,
    Hacktivation,
    AppManagement,
    DataManagement,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    pub fn from_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    pub fn contains(&self, capability: Capability) -> bool {
        self.0.contains(&capability)
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    ecid: Option<Ecid>,
    udid: Option<Udid>,
    product_type: ProductType,
    board_config: Option<BoardConfig>,
    soc: Soc,
}

impl DeviceIdentity {
    pub fn new(product_type: ProductType, soc: Soc) -> Self {
        Self {
            ecid: None,
            udid: None,
            product_type,
            board_config: None,
            soc,
        }
    }

    pub fn with_ecid(mut self, ecid: Ecid) -> Self {
        self.ecid = Some(ecid);
        self
    }

    pub fn with_udid(mut self, udid: Udid) -> Self {
        self.udid = Some(udid);
        self
    }

    pub fn with_board_config(mut self, board_config: BoardConfig) -> Self {
        self.board_config = Some(board_config);
        self
    }

    pub const fn ecid(&self) -> Option<Ecid> {
        self.ecid
    }

    pub fn udid(&self) -> Option<&Udid> {
        self.udid.as_ref()
    }

    pub fn product_type(&self) -> &ProductType {
        &self.product_type
    }

    pub fn board_config(&self) -> Option<&BoardConfig> {
        self.board_config.as_ref()
    }

    pub const fn soc(&self) -> Soc {
        self.soc
    }

    pub fn selector(&self) -> Option<DeviceSelector> {
        self.ecid
            .map(DeviceSelector::Ecid)
            .or_else(|| self.udid.clone().map(DeviceSelector::Udid))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum DeviceSelector {
    Ecid(Ecid),
    Udid(Udid),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    identity: DeviceIdentity,
    mode: DeviceMode,
    connection_id: ConnectionId,
    capabilities: CapabilitySet,
}

impl DeviceSnapshot {
    pub fn new(
        identity: DeviceIdentity,
        mode: DeviceMode,
        connection_id: ConnectionId,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            identity,
            mode,
            connection_id,
            capabilities,
        }
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecid_accepts_decimal_and_prefixed_hex() {
        assert_eq!("4660".parse(), Ok(Ecid::new(0x1234)));
        assert_eq!("0x1234".parse(), Ok(Ecid::new(0x1234)));
    }

    #[test]
    fn identity_prefers_ecid_for_cross_mode_selection() {
        let identity = DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
            .with_udid(Udid::from("normal-mode-id"))
            .with_ecid(Ecid::new(42));

        assert_eq!(
            identity.selector(),
            Some(DeviceSelector::Ecid(Ecid::new(42)))
        );
    }
}
