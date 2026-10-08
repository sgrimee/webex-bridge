//! Per-user macOS paths and strict directory permissions.

use anyhow::{bail, Context, Result};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Paths belonging to the per-user service, never to a project checkout.
pub struct Paths {
    /// Root application data directory.
    pub data: PathBuf,
    /// Runtime directory for the Unix socket and refresh lock.
    pub run: PathBuf,
    /// TOML configuration, never containing secrets.
    pub config: PathBuf,
    /// SQLite mirror (Step 2).
    pub mirror: PathBuf,
    /// Refresh lock, shared by the CLI and daemon.
    pub refresh_lock: PathBuf,
}

impl Paths {
    /// Discover this user's application support directory.
    pub fn discover() -> Result<Self> {
        let root = dirs::data_dir()
            .context("No application data directory available")?
            .join("webex-bridge");
        Ok(Self::under(root))
    }

    /// Construct paths beneath a specified root (also useful in tests).
    #[must_use]
    pub fn under(data: PathBuf) -> Self {
        Self {
            run: data.join("run"),
            config: data.join("config.toml"),
            mirror: data.join("bridge.db"),
            refresh_lock: data.join("run/refresh.lock"),
            data,
        }
    }

    /// Create required directories or reject insecure existing ones.
    pub fn ensure_dirs(&self) -> Result<()> {
        for path in [&self.data, &self.run] {
            if !path.exists() {
                DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .with_context(|| format!("Cannot create {}", path.display()))?;
            }
            check_mode(path, 0o700)?;
        }
        Ok(())
    }

    /// Open/create the refresh lock without making a world-readable file.
    pub fn open_refresh_lock(&self) -> Result<File> {
        self.ensure_dirs()?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.refresh_lock)?;
        check_mode(&self.refresh_lock, 0o600)?;
        Ok(file)
    }
}

/// Reject symbolic links, unexpected types, and any group/other access.
pub fn check_mode(path: &Path, required: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        bail!("{} is a symbolic link", path.display());
    }
    if (required == 0o700 && !meta.is_dir()) || (required == 0o600 && !meta.is_file()) {
        bail!("{} has the wrong file type", path.display());
    }
    if meta.permissions().mode() & 0o777 != required {
        bail!("{} must have mode {required:o}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loose_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        paths.ensure_dirs().unwrap();
        assert!(paths.open_refresh_lock().is_ok());
        fs::set_permissions(&paths.run, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(paths.ensure_dirs().is_err());
    }

    #[test]
    fn rejects_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bridge");
        std::os::unix::fs::symlink(temp.path(), &root).unwrap();
        assert!(Paths::under(root).ensure_dirs().is_err());
    }
}
