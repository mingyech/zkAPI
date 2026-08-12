//! Write-ahead request journal (spec section 5.2).
//!
//! The journal records the essential identifiers of an in-flight request so
//! that the wallet can recover to a consistent state after a crash. A journal
//! entry is written *before* calling the server and cleared only after the
//! resulting next state has been persisted atomically.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zkapi_types::wire::ApiRequestV2;
use zkapi_types::Felt252;

use crate::error::ClientError;

/// A write-ahead journal entry for a pending API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequestJournal {
    /// Whether a pending request exists (always `true` when written to disk).
    pub exists: bool,
    /// UUID of the client request.
    pub client_request_id: String,
    /// The nullifier consumed by this request.
    pub nullifier: Felt252,
    /// Hash of the request payload.
    pub payload_hash: Felt252,
    /// Client-side rerandomization used to build the request proof.
    pub user_rerandomization: Felt252,
    /// Wall-clock time when the journal was created (milliseconds since epoch).
    pub created_at_ms: u64,
    /// Complete prepared request for idempotent transport retry. This contains
    /// only public proof material and the already-authorized payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_request: Option<ApiRequestV2>,
}

impl PendingRequestJournal {
    /// Atomically write a journal entry to disk.
    ///
    /// Uses write-to-temp-then-rename to guarantee crash safety.
    pub fn write(path: &Path, journal: &PendingRequestJournal) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(journal)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("tmp");
        write_private_file(&tmp_path, json.as_bytes())?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Read the journal from disk, if it exists.
    ///
    /// Returns `None` when no journal file is present (normal steady state).
    pub fn read(path: &Path) -> Result<Option<PendingRequestJournal>, ClientError> {
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let journal: PendingRequestJournal =
            serde_json::from_str(&data).map_err(|e| ClientError::Serialization(e.to_string()))?;
        if journal.exists {
            Ok(Some(journal))
        } else {
            Ok(None)
        }
    }

    /// Delete the journal file after the next state has been persisted
    /// successfully.
    pub fn clear(path: &Path) -> Result<(), ClientError> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkapi_journal_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_write_and_read() {
        let dir = test_dir("write_and_read");
        let path = dir.join("journal.json");
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "test-uuid-1234".to_string(),
            nullifier: Felt252::from_u64(999),
            payload_hash: Felt252::from_u64(0xabcd),
            user_rerandomization: Felt252::from_u64(7),
            created_at_ms: 1700000000000,
            prepared_request: None,
        };
        PendingRequestJournal::write(&path, &journal).unwrap();
        let loaded = PendingRequestJournal::read(&path).unwrap().unwrap();
        assert_eq!(loaded.client_request_id, "test-uuid-1234");
        assert_eq!(loaded.nullifier, Felt252::from_u64(999));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_read_missing_returns_none() {
        let dir = test_dir("read_missing");
        let path = dir.join("nonexistent.json");
        assert!(PendingRequestJournal::read(&path).unwrap().is_none());
    }

    #[test]
    fn test_clear() {
        let dir = test_dir("clear");
        let path = dir.join("journal.json");
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "x".to_string(),
            nullifier: Felt252::ZERO,
            payload_hash: Felt252::ZERO,
            user_rerandomization: Felt252::ZERO,
            created_at_ms: 0,
            prepared_request: None,
        };
        PendingRequestJournal::write(&path, &journal).unwrap();
        assert!(path.exists());
        PendingRequestJournal::clear(&path).unwrap();
        assert!(!path.exists());
        assert!(PendingRequestJournal::read(&path).unwrap().is_none());
    }
}
