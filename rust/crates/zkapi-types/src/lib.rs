//! Shared types for the zkAPI protocol.
//!
//! This crate defines the canonical data structures used across client, server,
//! and proof systems. All field elements are represented as 32-byte big-endian
//! arrays internally and serialized as `0x`-prefixed lowercase hex strings in JSON.

pub mod domain;
pub mod felt;
pub mod inputs;
pub mod note;
pub mod serialization;
pub mod signature;
pub mod wire;

pub use domain::{DomainTag, DOMAIN_TAGS};
pub use felt::Felt252;
pub use inputs::{
    canonical_payload_hash, canonical_response_hash, public_output_hash_from_cairo_outputs,
    request_public_output_hash_from_outputs, withdrawal_public_output_hash_from_outputs,
    RequestPublicInputs, WithdrawalPublicInputs,
};
pub use note::{Note, NoteStatus, NullifierStatus, PendingWithdrawal};
pub use signature::XmssSignature;

/// Published server signing roots for one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochRoots {
    pub epoch: u32,
    pub state_root: Felt252,
    pub clear_root: Felt252,
}

pub fn lookup_state_root(roots: &[EpochRoots], epoch: u32) -> Option<Felt252> {
    roots
        .iter()
        .find(|entry| entry.epoch == epoch)
        .map(|entry| entry.state_root)
}

pub fn lookup_clear_root(roots: &[EpochRoots], epoch: u32) -> Option<Felt252> {
    roots
        .iter()
        .find(|entry| entry.epoch == epoch)
        .map(|entry| entry.clear_root)
}

#[cfg(test)]
mod epoch_roots_tests {
    use super::*;

    #[test]
    fn epoch_roots_round_trip_as_json() {
        let roots = EpochRoots {
            epoch: 7,
            state_root: Felt252::from_u64(11),
            clear_root: Felt252::from_u64(13),
        };
        let json = serde_json::to_string(&roots).unwrap();
        assert_eq!(serde_json::from_str::<EpochRoots>(&json).unwrap(), roots);
    }
}

/// Protocol version for v1.
pub const PROTOCOL_VERSION: u16 = 1;

/// Merkle tree depth.
pub const MERKLE_DEPTH: usize = 32;

/// XMSS tree height.
pub const XMSS_TREE_HEIGHT: usize = 20;

/// WOTS+ Winternitz parameter.
pub const WOTS_W: usize = 16;

/// WOTS+ digest length in bits.
pub const WOTS_N_BITS: usize = 248;

/// WOTS+ len1 = ceil(248 / 4) = 62.
pub const WOTS_LEN1: usize = 62;

/// WOTS+ len2 = 3.
pub const WOTS_LEN2: usize = 3;

/// WOTS+ total chain count.
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

/// Challenge period in seconds (24 hours).
pub const CHALLENGE_PERIOD: u64 = 86400;

/// The Stark field prime: P = 2^251 + 17 * 2^192 + 1
pub const STARK_PRIME_HEX: &str =
    "0x0800000000000011000000000000000000000000000000000000000000000001";

/// Genesis anchor value.
pub const GENESIS_ANCHOR: u64 = 1;

/// Statement type for request proofs.
pub const STATEMENT_TYPE_REQUEST: u8 = 1;

/// Statement type for withdrawal proofs.
pub const STATEMENT_TYPE_WITHDRAWAL: u8 = 2;
