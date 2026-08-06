//! Client private state per spec section 5.2.
//!
//! Each active note is represented by a `NoteState` struct that tracks the
//! current balance, blinding factor, commitment, anchor, and server-issued
//! state signature. The state is persisted atomically to disk so that the
//! wallet can always recover to a consistent point after a crash.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zkapi_types::{Felt252, XmssSignature};

use crate::error::ClientError;

/// Client-side private state for a single note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteState {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    /// Blinding factor serialized as 0x-prefixed lowercase hex.
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_sig_epoch: Option<u32>,
    pub state_sig_root: Option<Felt252>,
    pub state_sig: Option<XmssSignature>,
}

impl NoteState {
    /// Create genesis state after a successful on-chain deposit.
    ///
    /// The initial balance equals the deposit amount, the anchor is 1 (genesis),
    /// and no state signature exists yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_deposit(
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
        note_id: u32,
        secret_s: Felt252,
        deposit_amount: u128,
        expiry_ts: u64,
        balance_blinding: String,
        commitment_x: Felt252,
        commitment_y: Felt252,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            contract_address,
            note_id,
            secret_s,
            deposit_amount,
            expiry_ts,
            current_balance: deposit_amount,
            balance_blinding,
            current_commitment_x: commitment_x,
            current_commitment_y: commitment_y,
            current_anchor: Felt252::ONE, // genesis anchor
            is_genesis: true,
            state_sig_epoch: None,
            state_sig_root: None,
            state_sig: None,
        }
    }

    /// Compute the solvency bound that the proof must commit to.
    ///
    /// Per spec section 8.2 constraint 9:
    /// - When policy is disabled: `solvency_bound = request_charge_cap`
    /// - When policy is enabled: `solvency_bound = policy_charge_cap`
    pub fn solvency_bound(&self, policy_enabled: bool, charge_cap: u128, policy_cap: u128) -> u128 {
        if policy_enabled {
            policy_cap
        } else {
            charge_cap
        }
    }

    /// Persist the state atomically by writing to a temporary file and then
    /// renaming it into the target path. This guarantees that a crash at any
    /// point leaves either the old state or the new state on disk, never a
    /// partial write.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write to a sibling temp file, then atomically rename.
        let tmp_path = path.with_extension("tmp");
        write_private_file(&tmp_path, json.as_bytes())?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load state from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, ClientError> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Archive the state file by moving it into an `archive/` subdirectory
    /// alongside the original path, with a filename that includes the note id.
    /// This is called after a successful close or withdrawal.
    pub fn archive(&self, path: &Path) -> Result<(), ClientError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let archive_dir = parent.join("archive");
        fs::create_dir_all(&archive_dir)?;

        let filename = format!("note_{}_closed.json", self.note_id);
        let archive_path = archive_dir.join(filename);

        // Save a copy to the archive, then remove the active state file.
        self.save(&archive_path)?;
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
        let dir = std::env::temp_dir().join(format!("zkapi_notestate_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_new_from_deposit_genesis() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            0,
            Felt252::from_u64(42),
            1000,
            1700000000,
            "0x2a".to_string(),
            Felt252::from_u64(1),
            Felt252::from_u64(2),
        );
        assert!(state.is_genesis);
        assert_eq!(state.current_balance, 1000);
        assert_eq!(state.current_anchor, Felt252::ONE);
        assert!(state.state_sig.is_none());
    }

    #[test]
    fn test_solvency_bound_policy_disabled() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            0,
            Felt252::from_u64(1),
            1000,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        assert_eq!(state.solvency_bound(false, 100, 50), 100);
    }

    #[test]
    fn test_solvency_bound_policy_enabled() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            0,
            Felt252::from_u64(1),
            1000,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        assert_eq!(state.solvency_bound(true, 100, 50), 50);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = test_dir("save_load");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        state.save(&path).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.note_id, 7);
        assert_eq!(loaded.current_balance, 5000);
        assert_eq!(loaded.balance_blinding, "0xff");
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
    fn test_archive() {
        let dir = test_dir("archive");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            3,
            Felt252::from_u64(1),
            100,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        state.save(&path).unwrap();
        assert!(path.exists());

        state.archive(&path).unwrap();
        assert!(!path.exists());
        let archived = dir.join("archive").join("note_3_closed.json");
        assert!(archived.exists());
    }
}
