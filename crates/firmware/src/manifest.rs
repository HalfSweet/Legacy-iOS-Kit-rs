use std::io::{Read, Seek};

use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreBehavior {
    Erase,
    Update,
}

#[derive(Clone, Debug)]
pub struct BuildManifest {
    product_version: IosVersion,
    build_id: BuildId,
    supported_product_types: Vec<ProductType>,
    identities: Vec<BuildIdentity>,
}

impl BuildManifest {
    pub fn from_reader(reader: impl Read + Seek) -> Result<Self, FirmwareError> {
        let root = Value::from_reader(reader)?;
        let dictionary = root
            .as_dictionary()
            .ok_or(FirmwareError::RootNotDictionary)?;
        let product_version = IosVersion::new(required_string(dictionary, "ProductVersion")?);
        let build_id = BuildId::new(required_string(dictionary, "ProductBuildVersion")?);
        let supported_product_types = required_array(dictionary, "SupportedProductTypes")?
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .map(ProductType::from)
                    .ok_or_else(|| FirmwareError::UnexpectedValue("SupportedProductTypes".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let identities = required_array(dictionary, "BuildIdentities")?
            .iter()
            .map(BuildIdentity::from_value)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            product_version,
            build_id,
            supported_product_types,
            identities,
        })
    }

    pub fn product_version(&self) -> &IosVersion {
        &self.product_version
    }

    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    pub fn supported_product_types(&self) -> &[ProductType] {
        &self.supported_product_types
    }

    pub fn identities(&self) -> &[BuildIdentity] {
        &self.identities
    }

    pub fn select_identity(
        &self,
        board_config: &BoardConfig,
        behavior: RestoreBehavior,
    ) -> Result<&BuildIdentity, FirmwareError> {
        let matches = self
            .identities
            .iter()
            .filter(|identity| {
                identity.board_config() == board_config && identity.restore_behavior() == behavior
            })
            .collect::<Vec<_>>();

        match matches.as_slice() {
            [] => Err(FirmwareError::IdentityNotFound {
                board_config: board_config.clone(),
                behavior,
            }),
            [identity] => Ok(identity),
            _ => Err(FirmwareError::AmbiguousIdentity {
                board_config: board_config.clone(),
                behavior,
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BuildIdentity {
    board_config: BoardConfig,
    restore_behavior: RestoreBehavior,
    raw: Dictionary,
    manifest: Dictionary,
}

impl BuildIdentity {
    fn from_value(value: &Value) -> Result<Self, FirmwareError> {
        let dictionary = value
            .as_dictionary()
            .ok_or_else(|| FirmwareError::UnexpectedValue("BuildIdentities".into()))?;
        let info = required_dictionary(dictionary, "Info")?;
        let board_config = BoardConfig::new(normalize_board_config(required_string(
            info,
            "DeviceClass",
        )?));
        let restore_behavior = match required_string(info, "RestoreBehavior")? {
            "Erase" => RestoreBehavior::Erase,
            "Update" => RestoreBehavior::Update,
            value => return Err(FirmwareError::UnknownRestoreBehavior(value.to_owned())),
        };
        let manifest = required_dictionary(dictionary, "Manifest")?.clone();

        Ok(Self {
            board_config,
            restore_behavior,
            raw: dictionary.clone(),
            manifest,
        })
    }

    pub fn board_config(&self) -> &BoardConfig {
        &self.board_config
    }

    pub const fn restore_behavior(&self) -> RestoreBehavior {
        self.restore_behavior
    }

    pub fn component_path(&self, component: &str) -> Result<&str, FirmwareError> {
        let component = required_dictionary(&self.manifest, component)?;
        let info = required_dictionary(component, "Info")?;
        required_string(info, "Path")
    }

    pub fn component_paths(&self) -> impl Iterator<Item = (&str, &str)> {
        self.manifest.iter().filter_map(|(name, value)| {
            let component = value.as_dictionary()?;
            let info = component.get("Info")?.as_dictionary()?;
            let path = info.get("Path")?.as_string()?;
            Some((name.as_str(), path))
        })
    }

    pub fn manifest(&self) -> &Dictionary {
        &self.manifest
    }

    pub fn raw(&self) -> &Dictionary {
        &self.raw
    }
}

fn required_string<'a>(dictionary: &'a Dictionary, key: &str) -> Result<&'a str, FirmwareError> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .ok_or_else(|| FirmwareError::MissingValue(key.to_owned()))
}

fn required_array<'a>(dictionary: &'a Dictionary, key: &str) -> Result<&'a [Value], FirmwareError> {
    dictionary
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| FirmwareError::MissingValue(key.to_owned()))
}

fn required_dictionary<'a>(
    dictionary: &'a Dictionary,
    key: &str,
) -> Result<&'a Dictionary, FirmwareError> {
    dictionary
        .get(key)
        .and_then(Value::as_dictionary)
        .ok_or_else(|| FirmwareError::MissingValue(key.to_owned()))
}

fn normalize_board_config(board_config: &str) -> String {
    let normalized = board_config.to_ascii_lowercase();
    normalized
        .strip_suffix("ap")
        .unwrap_or(&normalized)
        .to_owned()
}

#[derive(Debug, Error)]
pub enum FirmwareError {
    #[error("firmware I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid firmware archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("firmware archive does not contain {0}")]
    ArchiveEntryNotFound(String),
    #[error("firmware entry {name} is {size} bytes, exceeding the {maximum} byte limit")]
    ArchiveEntryTooLarge {
        name: String,
        size: u64,
        maximum: u64,
    },
    #[error("failed to parse plist: {0}")]
    Plist(#[from] plist::Error),
    #[error("BuildManifest root is not a dictionary")]
    RootNotDictionary,
    #[error("BuildManifest is missing {0}")]
    MissingValue(String),
    #[error("BuildManifest contains an unexpected value at {0}")]
    UnexpectedValue(String),
    #[error("unknown restore behavior {0}")]
    UnknownRestoreBehavior(String),
    #[error("no {behavior:?} identity for {board_config}")]
    IdentityNotFound {
        board_config: BoardConfig,
        behavior: RestoreBehavior,
    },
    #[error("multiple {behavior:?} identities for {board_config}")]
    AmbiguousIdentity {
        board_config: BoardConfig,
        behavior: RestoreBehavior,
    },
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>ProductVersion</key><string>7.1.2</string>
  <key>ProductBuildVersion</key><string>11D257</string>
  <key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
  <key>BuildIdentities</key><array><dict>
    <key>Info</key><dict>
      <key>DeviceClass</key><string>n90ap</string>
      <key>RestoreBehavior</key><string>Erase</string>
    </dict>
    <key>Manifest</key><dict>
      <key>RestoreRamDisk</key><dict><key>Info</key><dict>
        <key>Path</key><string>038-0123-001.dmg</string>
      </dict></dict>
    </dict>
  </dict></array>
</dict></plist>"#;

    #[test]
    fn selects_identity_and_component_path() {
        let manifest = BuildManifest::from_reader(Cursor::new(MANIFEST)).unwrap();
        let identity = manifest
            .select_identity(&BoardConfig::from("n90"), RestoreBehavior::Erase)
            .unwrap();

        assert_eq!(manifest.product_version(), &IosVersion::from("7.1.2"));
        assert_eq!(manifest.build_id(), &BuildId::from("11D257"));
        assert_eq!(
            identity.component_path("RestoreRamDisk").unwrap(),
            "038-0123-001.dmg"
        );
        assert_eq!(
            identity.component_paths().collect::<Vec<_>>(),
            vec![("RestoreRamDisk", "038-0123-001.dmg")]
        );
    }
}
