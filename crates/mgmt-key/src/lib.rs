//! Finds the mgmt key the dashboard, the daemon and the QEMU harness share
//! with the kernel they talk to.
//!
//! The key comes from the `KERNEL_MGMT_KEY` environment variable or, when
//! that is unset, from the nearest `.mgmt-key.local` (the file `make
//! dev-key` writes) in a starting directory or one of its parents. Either
//! must hold 32 hex characters. There is no built-in fallback key.

use sec_core::security::hash::MgmtKey;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The environment variable holding the key as 32 hex characters.
pub const ENV_VAR: &str = "KERNEL_MGMT_KEY";

/// The file `make dev-key` writes the key to.
pub const KEY_FILE: &str = ".mgmt-key.local";

/// Why no key was found.
#[derive(Debug)]
pub enum KeyError {
    /// [`ENV_VAR`] is set but is not 32 hex characters.
    BadEnv,
    /// A key file exists but could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// A key file does not hold 32 hex characters.
    BadFile(PathBuf),
    /// [`ENV_VAR`] is unset and no key file was found.
    Missing,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadEnv => write!(f, "{ENV_VAR} must be 32 hex characters"),
            Self::Unreadable { path, .. } => write!(f, "cannot read {}", path.display()),
            Self::BadFile(path) => write!(f, "{} must hold 32 hex characters", path.display()),
            Self::Missing => write!(
                f,
                "no mgmt key: set {ENV_VAR}=<32 hex> or run `make dev-key` to write {KEY_FILE}"
            ),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            Self::BadEnv | Self::BadFile(_) | Self::Missing => None,
        }
    }
}

/// The key from [`ENV_VAR`], or else from the nearest [`KEY_FILE`] in
/// `start` or one of its parents.
///
/// # Errors
///
/// A [`KeyError`] when the variable or the file nearest `start` does not
/// hold a key, or neither exists.
pub fn load(start: &Path) -> Result<MgmtKey, KeyError> {
    resolve(
        std::env::var(ENV_VAR).ok().as_deref(),
        start,
        read_if_present,
    )
}

/// [`load`] given the variable's value and a way to read a file that
/// returns `None` when it does not exist.
fn resolve(
    env_value: Option<&str>,
    start: &Path,
    read: impl Fn(&Path) -> io::Result<Option<String>>,
) -> Result<MgmtKey, KeyError> {
    if let Some(hex) = env_value {
        return MgmtKey::parse_hex(hex.trim()).ok_or(KeyError::BadEnv);
    }
    for dir in start.ancestors() {
        let path = dir.join(KEY_FILE);
        let contents = read(&path).map_err(|source| KeyError::Unreadable {
            path: path.clone(),
            source,
        })?;
        if let Some(hex) = contents {
            return MgmtKey::parse_hex(hex.trim()).ok_or(KeyError::BadFile(path));
        }
    }
    Err(KeyError::Missing)
}

fn read_if_present(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const HEX: &str = "00112233445566778899aabbccddeeff";
    const OTHER_HEX: &str = "ffeeddccbbaa99887766554433221100";

    fn key_bytes(hex: &str) -> [u8; 16] {
        MgmtKey::parse_hex(hex).unwrap().to_bytes()
    }

    /// A reader over `files`, keyed by path.
    fn files(files: &[(&str, &str)]) -> impl Fn(&Path) -> io::Result<Option<String>> + use<> {
        let files: HashMap<PathBuf, String> = files
            .iter()
            .map(|&(path, contents)| (PathBuf::from(path), contents.to_string()))
            .collect();
        move |path| Ok(files.get(path).cloned())
    }

    #[test]
    fn the_variable_wins_over_any_file() {
        let read = files(&[("/a/.mgmt-key.local", OTHER_HEX)]);

        let found = resolve(Some(HEX), Path::new("/a"), read).unwrap();

        assert_eq!(found.to_bytes(), key_bytes(HEX));
    }

    #[test]
    fn a_bad_variable_is_an_error_even_with_a_file() {
        let read = files(&[("/a/.mgmt-key.local", HEX)]);

        let found = resolve(Some("not hex"), Path::new("/a"), read);

        assert!(matches!(found, Err(KeyError::BadEnv)));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let read = files(&[("/a/.mgmt-key.local", &format!("{HEX}\n"))]);

        assert_eq!(
            resolve(Some(&format!(" {HEX} ")), Path::new("/"), files(&[]))
                .unwrap()
                .to_bytes(),
            key_bytes(HEX)
        );
        assert_eq!(
            resolve(None, Path::new("/a"), read).unwrap().to_bytes(),
            key_bytes(HEX)
        );
    }

    #[test]
    fn the_nearest_file_up_the_tree_is_used() {
        let read = files(&[
            ("/a/.mgmt-key.local", OTHER_HEX),
            ("/a/b/.mgmt-key.local", HEX),
        ]);

        let found = resolve(None, Path::new("/a/b/c/d"), read).unwrap();

        assert_eq!(found.to_bytes(), key_bytes(HEX));
    }

    #[test]
    fn a_bad_nearest_file_is_an_error_not_skipped() {
        let read = files(&[
            ("/a/.mgmt-key.local", HEX),
            ("/a/b/.mgmt-key.local", "short"),
        ]);

        let found = resolve(None, Path::new("/a/b"), read);

        assert!(
            matches!(found, Err(KeyError::BadFile(path)) if path == Path::new("/a/b/.mgmt-key.local"))
        );
    }

    #[test]
    fn an_unreadable_file_is_an_error() {
        let read = |_: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));

        let found = resolve(None, Path::new("/a"), read);

        assert!(matches!(found, Err(KeyError::Unreadable { .. })));
    }

    #[test]
    fn no_variable_and_no_file_is_missing() {
        let found = resolve(None, Path::new("/a/b"), files(&[]));

        assert!(matches!(found, Err(KeyError::Missing)));
    }
}
