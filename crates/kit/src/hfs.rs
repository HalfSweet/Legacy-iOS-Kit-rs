use std::{
    fmt,
    io::Write,
    path::{Path, PathBuf},
};

use legacy_ios_image::{HfsEntryKind, HfsImage};
use serde::Serialize;

use crate::KitError;

#[derive(Clone, Debug)]
pub enum HfsMutation {
    Grow {
        size: usize,
    },
    AddFile {
        path: String,
        data: Vec<u8>,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    CreateDirectory {
        path: String,
    },
    Move {
        source: String,
        destination: String,
    },
    Chmod {
        path: String,
        mode: u16,
    },
    Chown {
        path: String,
        owner: u32,
        group: u32,
    },
    Untar {
        archive: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HfsKind {
    File,
    Directory,
    Symlink,
}

impl From<HfsEntryKind> for HfsKind {
    fn from(value: HfsEntryKind) -> Self {
        match value {
            HfsEntryKind::File => Self::File,
            HfsEntryKind::Directory => Self::Directory,
            HfsEntryKind::Symlink => Self::Symlink,
        }
    }
}

impl fmt::Display for HfsKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HfsEntrySummary {
    name: String,
    kind: HfsKind,
    size: u64,
}

impl HfsEntrySummary {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> HfsKind {
        self.kind
    }

    pub const fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HfsStatSummary {
    cnid: u32,
    kind: HfsKind,
    size: u64,
    owner: u32,
    group: u32,
    mode: u16,
}

impl HfsStatSummary {
    pub const fn cnid(&self) -> u32 {
        self.cnid
    }

    pub const fn kind(&self) -> HfsKind {
        self.kind
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn owner(&self) -> u32 {
        self.owner
    }

    pub const fn group(&self) -> u32 {
        self.group
    }

    pub const fn mode(&self) -> u16 {
        self.mode
    }
}

pub(crate) async fn list(image: PathBuf, path: String) -> Result<Vec<HfsEntrySummary>, KitError> {
    let data = tokio::fs::read(image).await?;
    tokio::task::spawn_blocking(move || {
        Ok(HfsImage::parse(data)?
            .list(&path)?
            .into_iter()
            .map(|entry| HfsEntrySummary {
                name: entry.name().to_owned(),
                kind: entry.kind().into(),
                size: entry.size(),
            })
            .collect())
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))?
}

pub(crate) async fn stat(image: PathBuf, path: String) -> Result<HfsStatSummary, KitError> {
    let data = tokio::fs::read(image).await?;
    tokio::task::spawn_blocking(move || {
        let stat = HfsImage::parse(data)?.stat(&path)?;
        Ok(HfsStatSummary {
            cnid: stat.cnid(),
            kind: stat.kind().into(),
            size: stat.size(),
            owner: stat.owner(),
            group: stat.group(),
            mode: stat.mode(),
        })
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))?
}

pub(crate) async fn extract(
    image: PathBuf,
    path: String,
    destination: PathBuf,
) -> Result<(), KitError> {
    let data = tokio::fs::read(image).await?;
    let contents = tokio::task::spawn_blocking(move || HfsImage::parse(data)?.read(&path))
        .await
        .map_err(|error| KitError::Task(error.to_string()))??;
    write_atomic(destination, contents).await
}

pub(crate) async fn edit(
    source: PathBuf,
    destination: PathBuf,
    mutations: Vec<HfsMutation>,
) -> Result<(), KitError> {
    let data = tokio::fs::read(source).await?;
    let data = tokio::task::spawn_blocking(move || {
        let mut image = HfsImage::parse(data)?;
        for mutation in mutations {
            match mutation {
                HfsMutation::Grow { size } => image.grow(size)?,
                HfsMutation::AddFile { path, data } => image.add_file(&path, &data)?,
                HfsMutation::Remove { path, recursive } => image.remove(&path, recursive)?,
                HfsMutation::CreateDirectory { path } => image.mkdir(&path)?,
                HfsMutation::Move {
                    source,
                    destination,
                } => image.move_entry(&source, &destination)?,
                HfsMutation::Chmod { path, mode } => image.chmod(&path, mode)?,
                HfsMutation::Chown { path, owner, group } => image.chown(&path, owner, group)?,
                HfsMutation::Untar { archive } => image.untar(&archive)?,
            }
        }
        Ok::<_, legacy_ios_image::HfsError>(image.into_bytes())
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    write_atomic(destination, data).await
}

async fn write_atomic(destination: PathBuf, data: Vec<u8>) -> Result<(), KitError> {
    tokio::task::spawn_blocking(move || {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&data)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(destination)
            .map_err(|error| error.error)?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    Ok(())
}
