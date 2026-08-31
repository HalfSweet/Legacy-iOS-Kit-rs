use std::{collections::BTreeMap, fmt, sync::OnceLock};

use serde::Deserialize;

use crate::AssetError;

const BUNDLED_RESOURCES: &str = include_str!("../data/resources.toml");

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Redistribution {
    Bundled,
    DownloadOnly,
    Prohibited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    id: ResourceId,
    source_url: String,
    source_commit: String,
    sha256: String,
    size: u64,
    purpose: String,
    redistribution: Redistribution,
}

impl ResourceRecord {
    pub fn id(&self) -> &ResourceId {
        &self.id
    }

    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub const fn redistribution(&self) -> Redistribution {
        self.redistribution
    }
}

#[derive(Clone, Debug)]
pub struct ResourceCatalog {
    schema_version: u32,
    baseline_commit: String,
    records: BTreeMap<ResourceId, ResourceRecord>,
}

impl ResourceCatalog {
    pub fn bundled() -> &'static Self {
        static CATALOG: OnceLock<ResourceCatalog> = OnceLock::new();
        CATALOG.get_or_init(|| {
            Self::parse(BUNDLED_RESOURCES).expect("bundled resource catalog must be valid")
        })
    }

    pub fn parse(source: &str) -> Result<Self, AssetError> {
        let raw: RawCatalog = toml::from_str(source)?;
        if raw.schema_version != 1 {
            return Err(AssetError::UnsupportedSchema(raw.schema_version));
        }
        let mut records = BTreeMap::new();
        for raw in raw.resources {
            if raw.sha256.len() != 64 || !raw.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(AssetError::InvalidDigest(raw.id));
            }
            let id = ResourceId::new(raw.id);
            let record = ResourceRecord {
                id: id.clone(),
                source_url: raw.source_url,
                source_commit: raw.source_commit,
                sha256: raw.sha256,
                size: raw.size,
                purpose: raw.purpose,
                redistribution: raw.redistribution,
            };
            if records.insert(id.clone(), record).is_some() {
                return Err(AssetError::DuplicateResource(id));
            }
        }
        Ok(Self {
            schema_version: raw.schema_version,
            baseline_commit: raw.baseline_commit,
            records,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn baseline_commit(&self) -> &str {
        &self.baseline_commit
    }

    pub fn get(&self, id: &ResourceId) -> Option<&ResourceRecord> {
        self.records.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ResourceRecord> {
        self.records.values()
    }
}

#[derive(Deserialize)]
struct RawCatalog {
    schema_version: u32,
    baseline_commit: String,
    resources: Vec<RawResource>,
}

#[derive(Deserialize)]
struct RawResource {
    id: String,
    source_url: String,
    source_commit: String,
    sha256: String,
    size: u64,
    purpose: String,
    redistribution: Redistribution,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_resources_have_fixed_provenance() {
        let catalog = ResourceCatalog::bundled();
        assert_eq!(catalog.iter().count(), 10);
        let resource = catalog.get(&ResourceId::new("ios4-scab-template")).unwrap();
        assert_eq!(resource.sha256().len(), 64);
        assert_eq!(resource.redistribution(), Redistribution::DownloadOnly);
        assert_eq!(resource.source_commit(), catalog.baseline_commit());
    }
}
