//! Note leaf computation.
//!
//! leaf = Poseidon(domain("zkapi.leaf"), note_id, C, D, expiry_ts)

use zkapi_types::Felt252;

/// Compute the active note leaf.
///
/// `leaf = Poseidon(domain("zkapi.leaf"), note_id, commitment, deposit_amount, expiry_ts)`
pub fn compute_note_leaf(
    note_id: u32,
    commitment: &Felt252,
    deposit_amount: u128,
    expiry_ts: u64,
) -> Felt252 {
    crate::v2::note_leaf(note_id, commitment, deposit_amount, expiry_ts)
}

/// Compute the registration commitment.
///
/// `C = Poseidon(domain("zkapi.reg"), s, 0)`
pub fn compute_registration_commitment(secret: &Felt252) -> Felt252 {
    crate::v2::registration_commitment(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_leaf_deterministic() {
        let commitment = Felt252::from_u64(12345);
        let l1 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        let l2 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        assert_eq!(l1, l2);
    }

    #[test]
    fn test_note_leaf_different_ids() {
        let commitment = Felt252::from_u64(12345);
        let l1 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        let l2 = compute_note_leaf(1, &commitment, 1000, 1700000000);
        assert_ne!(l1, l2);
    }

    #[test]
    fn test_registration_commitment() {
        let secret = Felt252::from_u64(42);
        let c1 = compute_registration_commitment(&secret);
        let c2 = compute_registration_commitment(&secret);
        assert_eq!(c1, c2);
        assert!(!c1.is_zero());
    }
}
