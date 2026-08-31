//! Inode ↔ AFC path table for the FUSE backend.
//!
//! The kernel addresses entries by inode while AFC addresses them by path.
//! Inodes are assigned on first lookup and never reclaimed (forget calls are
//! ignored): mounts are short-lived interactive sessions, so the bounded
//! growth of one table entry per visited path is acceptable.

use std::collections::HashMap;

use super::attr::ROOT_INO;

#[derive(Debug)]
pub(crate) struct InodeTable {
    /// Index 0 holds the root path; inode numbers are index + 1.
    paths: Vec<String>,
    by_path: HashMap<String, u64>,
}

impl InodeTable {
    pub(crate) fn new() -> Self {
        let mut table = Self {
            paths: Vec::new(),
            by_path: HashMap::new(),
        };
        assert_eq!(table.intern("/"), ROOT_INO);
        table
    }

    /// Return the inode for `path`, assigning a new one on first sight.
    pub(crate) fn intern(&mut self, path: &str) -> u64 {
        if let Some(ino) = self.by_path.get(path) {
            return *ino;
        }
        let ino = self.paths.len() as u64 + 1;
        self.paths.push(path.to_owned());
        self.by_path.insert(path.to_owned(), ino);
        ino
    }

    pub(crate) fn path(&self, ino: u64) -> Option<&str> {
        if ino == 0 {
            return None;
        }
        self.paths.get((ino - 1) as usize).map(String::as_str)
    }

    /// Join `name` onto the path of `parent`.
    pub(crate) fn child_path(&self, parent: u64, name: &str) -> Option<String> {
        let parent = self.path(parent)?;
        Some(if parent == "/" {
            format!("/{name}")
        } else {
            format!("{parent}/{name}")
        })
    }

    /// Inode of the parent of `ino`; the parent of the root is the root.
    pub(crate) fn parent_ino(&self, ino: u64) -> Option<u64> {
        let path = self.path(ino)?;
        let parent = match path.rfind('/') {
            Some(0) | None => "/",
            Some(index) => &path[..index],
        };
        // The parent was interned before any of its children.
        self.by_path.get(parent).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_inode_one() {
        let table = InodeTable::new();
        assert_eq!(table.path(ROOT_INO), Some("/"));
        assert_eq!(table.path(0), None);
        assert_eq!(table.path(2), None);
    }

    #[test]
    fn interning_is_stable_and_dense() {
        let mut table = InodeTable::new();
        assert_eq!(table.intern("/DCIM"), 2);
        assert_eq!(table.intern("/DCIM"), 2);
        assert_eq!(table.intern("/DCIM/100APPLE"), 3);
        assert_eq!(table.path(3), Some("/DCIM/100APPLE"));
    }

    #[test]
    fn joins_child_paths() {
        let mut table = InodeTable::new();
        let dcim = table.intern("/DCIM");
        assert_eq!(table.child_path(ROOT_INO, "a"), Some("/a".to_owned()));
        assert_eq!(table.child_path(dcim, "b"), Some("/DCIM/b".to_owned()));
        assert_eq!(table.child_path(99, "x"), None);
    }

    #[test]
    fn resolves_parent_inodes() {
        let mut table = InodeTable::new();
        let dcim = table.intern("/DCIM");
        let child = table.intern("/DCIM/100APPLE");
        assert_eq!(table.parent_ino(child), Some(dcim));
        assert_eq!(table.parent_ino(ROOT_INO), Some(ROOT_INO));
    }
}
