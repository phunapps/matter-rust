//! Default filesystem-backed [`ControllerStore`].

use std::path::PathBuf;

use super::{ControllerStore, StoreError};

/// Stores the snapshot blob as a single file.
///
/// Writes are atomic (temp file + rename) and, on Unix, the file is
/// created with `0600` permissions. The blob holds private keys in the
/// clear: protect the containing directory, or supply a custom
/// [`ControllerStore`] backed by an encrypted store.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Create a store backed by `path`. The file need not exist yet.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ControllerStore for FileStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    fn save(&self, snapshot: &[u8]) -> Result<(), StoreError> {
        use std::io::Write;

        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(snapshot)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("matter-controller-test-{name}"));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("tmp"));
        p
    }

    #[test]
    fn load_missing_returns_none() {
        let store = FileStore::new(temp_path("missing"));
        assert!(store.load().expect("load ok").is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = temp_path("roundtrip");
        let store = FileStore::new(&path);
        store.save(b"hello snapshot").expect("save ok");
        assert_eq!(
            store.load().expect("load ok"),
            Some(b"hello snapshot".to_vec())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_overwrites_atomically() {
        let path = temp_path("overwrite");
        let store = FileStore::new(&path);
        store.save(b"first").expect("save 1");
        store.save(b"second value longer").expect("save 2");
        assert_eq!(store.load().expect("load").unwrap(), b"second value longer");
        // temp file must not linger
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        let store = FileStore::new(&path);
        store.save(b"secret").expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
