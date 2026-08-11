//! Nullifier computation.
//!
//! x = Poseidon(domain("zkapi.null"), s, tau)
//! For genesis: tau = 1
//! For later states: tau = server-issued anchor

use zkapi_types::Felt252;

/// Compute a nullifier from the user secret and state anchor.
pub fn compute_nullifier(secret: &Felt252, anchor: &Felt252) -> Felt252 {
    crate::v2::nullifier(secret, anchor)
}

/// Compute the genesis nullifier.
pub fn compute_genesis_nullifier(secret: &Felt252) -> Felt252 {
    compute_nullifier(secret, &Felt252::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let secret = Felt252::from_u64(42);
        let anchor = Felt252::from_u64(100);
        let n1 = compute_nullifier(&secret, &anchor);
        let n2 = compute_nullifier(&secret, &anchor);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_genesis_nullifier() {
        let secret = Felt252::from_u64(42);
        let n_genesis = compute_genesis_nullifier(&secret);
        let n_manual = compute_nullifier(&secret, &Felt252::ONE);
        assert_eq!(n_genesis, n_manual);
    }

    #[test]
    fn test_different_anchors() {
        let secret = Felt252::from_u64(42);
        let n1 = compute_nullifier(&secret, &Felt252::from_u64(1));
        let n2 = compute_nullifier(&secret, &Felt252::from_u64(2));
        assert_ne!(n1, n2);
    }
}
