use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, anyhow};
use directories::ProjectDirs;
use legacy_ios_kit::NormalBackend;
use serde::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;

use crate::OutputFormat;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AppConfig {
    #[serde(skip)]
    pub(crate) path: PathBuf,
    pub(crate) output: Option<OutputFormat>,
    pub(crate) log: Option<String>,
    pub(crate) storage: StorageConfig,
    pub(crate) transport: TransportConfig,
    pub(crate) network: NetworkConfig,
}

impl AppConfig {
    pub(crate) fn load(explicit: Option<&Path>) -> Result<Self> {
        let environment_path = env::var_os("LIK_CONFIG").map(PathBuf::from);
        let path = explicit
            .map(Path::to_owned)
            .or(environment_path)
            .unwrap_or(default_path()?);
        let required = explicit.is_some() || env::var_os("LIK_CONFIG").is_some();
        let mut config = if path.exists() {
            let source = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str(&source)
                .with_context(|| format!("failed to parse {}", path.display()))?
        } else if required {
            return Err(anyhow!(
                "configuration file does not exist: {}",
                path.display()
            ));
        } else {
            Self::default()
        };
        config.path = path;
        if let Ok(output) = env::var("LIK_OUTPUT") {
            config.output = Some(match output.as_str() {
                "human" => OutputFormat::Human,
                "json" => OutputFormat::Json,
                _ => return Err(anyhow!("LIK_OUTPUT must be human or json")),
            });
        }
        if let Ok(log) = env::var("LIK_LOG") {
            config.log = Some(log);
        }
        Ok(config)
    }

    pub(crate) fn log_level(&self) -> Result<LevelFilter> {
        self.log
            .as_deref()
            .map(LevelFilter::from_str)
            .transpose()
            .map_err(|error| anyhow!("invalid log level: {error}"))
            .map(|value| value.unwrap_or(LevelFilter::INFO))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct StorageConfig {
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) data_dir: Option<PathBuf>,
    pub(crate) work_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TransportConfig {
    pub(crate) normal_backend: NormalBackend,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NetworkConfig {
    pub(crate) firmware_catalog: Option<String>,
    pub(crate) tss_endpoint: Option<String>,
    pub(crate) resource_base: Option<String>,
    pub(crate) download_concurrency: Option<usize>,
}

fn default_path() -> Result<PathBuf> {
    let directories = ProjectDirs::from("dev", "Legacy-iOS-Kit", "legacy-ios-kit")
        .ok_or_else(|| anyhow!("unable to determine configuration directory"))?;
    Ok(directories.config_dir().join("config.toml"))
}
