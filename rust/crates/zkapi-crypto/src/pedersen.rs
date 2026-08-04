//! Pedersen commitment on the Stark curve.
//!
//! E(B, r) = B * G_balance + r * H_blind
//!
//! This is the ONLY non-post-quantum component in v1.
//! It is required for homomorphic addition and rerandomization.
//!
//! G_balance and H_blind are fixed independent generators derived offline
//! from the labels "zkapi.bal.g" and "zkapi.bal.h" using try-and-increment
//! hash-to-curve.
//! They are committed as protocol constants.

use std::ops::Neg;

use num_bigint::BigUint;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Type alias for API compatibility with downstream code that uses
/// `FieldElement`.
pub type FieldElement = Felt;

/// Order of the Stark curve cyclic group (`EC_ORDER`, denoted `n`).
///
/// Pedersen blinding factors are scalars in `Z/nZ`: scalar multiplication
/// `k * H` only depends on `k mod n`. Crucially `n < p`, the base-field prime
/// behind [`Felt`]. Accumulating blinding with base-field (`Felt`) addition is
/// therefore a latent bug — once a running blinding crosses `p` the `Felt`
/// result wraps by `p`, which does not match the `mod n` semantics of
/// [`PedersenCommitment::commit`], so the stored blinding silently stops
/// opening the committed point. All blinding arithmetic must reduce modulo `n`.
pub const CURVE_ORDER_HEX: &str =
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

fn curve_order() -> BigUint {
    BigUint::parse_bytes(CURVE_ORDER_HEX.as_bytes(), 16).expect("CURVE_ORDER_HEX is valid hex")
}

fn biguint_to_felt(value: BigUint) -> Felt {
    let bytes = value.to_bytes_be();
    let mut buf = [0u8; 32];
    // `value` is reduced mod n < p, so it fits in <= 32 bytes.
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Felt::from_bytes_be(&buf)
}

/// Reduce a blinding scalar modulo the curve order `n`.
pub fn reduce_blinding(value: &Felt) -> Felt {
    biguint_to_felt(value.to_biguint() % curve_order())
}

/// Add two Pedersen blinding scalars modulo the curve order `n`.
///
/// This is the canonical way to accumulate blinding factors across
/// rerandomization and homomorphic server updates; see [`CURVE_ORDER_HEX`].
pub fn add_blinding(a: &Felt, b: &Felt) -> Felt {
    biguint_to_felt((a.to_biguint() + b.to_biguint()) % curve_order())
}

/// G_balance generator coordinates.
///
/// Reproducible derivation:
/// `keccak256("zkapi.pedersen.h2c.v1" || "zkapi.bal.g" || counter_be32)`,
/// try counters from zero, reduce digest to an x coordinate, and accept the
/// first x whose Stark curve equation has a square root. The even y root is
/// selected. For this label the accepted counter is 0.
pub const G_BALANCE_X_HEX: &str =
    "02e60e3230fe061dbebac8fd2cfa503e4eb92783aeb5fd6fb931a66ee277e4d3";
pub const G_BALANCE_Y_HEX: &str =
    "039289536a4fb4c04778f51eed313db47730cf86d342fd3f80f27bed1c2febac";

/// H_blind generator coordinates, derived with the same procedure from
/// "zkapi.bal.h". The accepted counter is 0.
pub const H_BLIND_X_HEX: &str = "009ed31288dc3e29f8759144b455aa05f39eee1a947e92fc1a9d71d15ed49faa";
pub const H_BLIND_Y_HEX: &str = "073853a56a47d4dbeaf5c18ca78fbf64f414d5fccefaac0227d5c2654d2ca9b4";

fn scalar_mul(point: &ProjectivePoint, scalar: &Felt) -> ProjectivePoint {
    let bits = scalar.to_bits_le();
    let mut result = ProjectivePoint::identity();
    let mut temp = point.clone();
    for bit in bits.iter() {
        if *bit {
            result = &result + &temp;
        }
        temp = &temp + &temp;
    }
    result
}

lazy_static::lazy_static! {
    /// G_balance generator point.
    pub static ref G_BALANCE: ProjectivePoint = {
        ProjectivePoint::from_affine(
            Felt::from_hex_unchecked(G_BALANCE_X_HEX),
            Felt::from_hex_unchecked(G_BALANCE_Y_HEX),
        ).expect("G_BALANCE constant must be on curve")
    };

    /// H_blind generator point.
    pub static ref H_BLIND: ProjectivePoint = {
        ProjectivePoint::from_affine(
            Felt::from_hex_unchecked(H_BLIND_X_HEX),
            Felt::from_hex_unchecked(H_BLIND_Y_HEX),
        ).expect("H_BLIND constant must be on curve")
    };
}

/// A Pedersen commitment E(B, r) = B * G_balance + r * H_blind.
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    pub point: ProjectivePoint,
}

impl PedersenCommitment {
    /// Create a new commitment from balance and blinding factor.
    pub fn commit(balance: u128, blinding: &Felt) -> Self {
        let b_scalar = Felt::from(balance);
        let bg = scalar_mul(&G_BALANCE, &b_scalar);
        let rh = scalar_mul(&H_BLIND, blinding);
        Self { point: &bg + &rh }
    }

    /// Rerandomize: E(B, r + rho) = E(B, r) + rho * H_blind.
    pub fn rerandomize(&self, rho: &Felt) -> Self {
        let rho_h = scalar_mul(&H_BLIND, rho);
        Self {
            point: &self.point + &rho_h,
        }
    }

    /// Server update: subtract charge and add server blinding.
    ///
    /// E(B - delta, r + rho + blind_delta) =
    ///   E(B, r) + rho * H - delta * G + blind_delta * H
    ///
    /// Since the server operates on the already-rerandomized commitment (anon_commitment),
    /// this simplifies to:
    ///   anon_commitment - delta * G + blind_delta * H
    pub fn server_update(
        anon_commitment: &ProjectivePoint,
        charge: u128,
        blind_delta: &Felt,
    ) -> Self {
        let delta_scalar = Felt::from(charge);
        let delta_g = scalar_mul(&G_BALANCE, &delta_scalar);
        let blind_h = scalar_mul(&H_BLIND, blind_delta);
        // anon - delta*G + blind*H
        let neg_delta_g = delta_g.neg();
        let result = &(anon_commitment + &neg_delta_g) + &blind_h;
        Self { point: result }
    }

    /// Get the affine coordinates.
    pub fn to_affine(&self) -> (Felt, Felt) {
        let affine = self.point.to_affine().unwrap();
        (affine.x(), affine.y())
    }

    /// Verify that a commitment opens to the given values.
    pub fn verify_opening(&self, balance: u128, blinding: &Felt) -> bool {
        let expected = Self::commit(balance, blinding);
        self.point == expected.point
    }
}

/// Convert a ProjectivePoint to affine (x, y) Felt values.
pub fn point_to_affine(p: &ProjectivePoint) -> Option<(Felt, Felt)> {
    let affine = p.to_affine().ok()?;
    Some((affine.x(), affine.y()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generators_are_different() {
        let g_affine = G_BALANCE.to_affine().unwrap();
        let h_affine = H_BLIND.to_affine().unwrap();
        assert_ne!(g_affine.x(), h_affine.x());
    }

    #[test]
    fn test_generators_match_committed_constants() {
        let g = G_BALANCE.to_affine().unwrap();
        let h = H_BLIND.to_affine().unwrap();
        assert_eq!(g.x(), Felt::from_hex_unchecked(G_BALANCE_X_HEX));
        assert_eq!(g.y(), Felt::from_hex_unchecked(G_BALANCE_Y_HEX));
        assert_eq!(h.x(), Felt::from_hex_unchecked(H_BLIND_X_HEX));
        assert_eq!(h.y(), Felt::from_hex_unchecked(H_BLIND_Y_HEX));
    }

    #[test]
    fn old_scalar_multiple_derivation_allows_reopening() {
        let public_a = Felt::from(11u64);
        let public_b = Felt::ONE;
        let old_g = scalar_mul(&G_BALANCE, &public_a);
        let old_h = scalar_mul(&G_BALANCE, &public_b);

        let balance = 1_000u64;
        let blinding = Felt::from(42u64);
        let commitment = &scalar_mul(&old_g, &Felt::from(balance)) + &scalar_mul(&old_h, &blinding);

        let forged_balance = 999u64;
        let forged_blinding = blinding + (Felt::from(balance - forged_balance) * public_a);
        let forged = &scalar_mul(&old_g, &Felt::from(forged_balance))
            + &scalar_mul(&old_h, &forged_blinding);

        assert_eq!(commitment, forged);
    }

    #[test]
    fn test_commit_and_verify() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let c = PedersenCommitment::commit(balance, &blinding);
        let (x, y) = c.to_affine();
        assert_eq!(
            x,
            Felt::from_hex_unchecked(
                "077bd464e41fd97fc8eb7b2cf070fc6f3d7587707446b027e0c6b60a29a05eae"
            )
        );
        assert_eq!(
            y,
            Felt::from_hex_unchecked(
                "023fd385119e903dd48d501552b1fb84e6e61a4685fe4d7ee4a6b71063a05611"
            )
        );
        assert!(c.verify_opening(balance, &blinding));
        assert!(!c.verify_opening(999, &blinding));
    }

    #[test]
    fn test_negative_openings_for_distinct_values() {
        let cases = [
            (0u128, 1u64, 1u128, 1u64),
            (1u128, 2u64, 2u128, 2u64),
            (100u128, 42u64, 99u128, 42u64),
            (u64::MAX as u128, 123u64, u64::MAX as u128, 124u64),
            (
                u128::from(u64::MAX) + 7,
                99u64,
                u128::from(u64::MAX) + 8,
                99u64,
            ),
        ];

        for (balance, blinding, wrong_balance, wrong_blinding) in cases {
            let commitment = PedersenCommitment::commit(balance, &Felt::from(blinding));
            assert!(!commitment.verify_opening(wrong_balance, &Felt::from(wrong_blinding)));
        }
    }

    #[test]
    fn test_rerandomization() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let c = PedersenCommitment::commit(balance, &blinding);

        let rho = Felt::from(7u64);
        let c_rerand = c.rerandomize(&rho);

        // The rerandomized commitment should open with blinding + rho
        let new_blinding = blinding + rho;
        assert!(c_rerand.verify_opening(balance, &new_blinding));
    }

    #[test]
    fn test_server_update_algebra() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let rho = Felt::from(7u64);

        // Client commits and rerandomizes
        let c = PedersenCommitment::commit(balance, &blinding);
        let anon = c.rerandomize(&rho);

        // Server applies charge
        let charge = 100u128;
        let blind_delta = Felt::from(13u64);
        let updated = PedersenCommitment::server_update(&anon.point, charge, &blind_delta);

        // Verify: E(B - charge, blinding + rho + blind_delta)
        let expected_balance = balance - charge;
        let expected_blinding = blinding + rho + blind_delta;
        assert!(updated.verify_opening(expected_balance, &expected_blinding));
    }

    #[test]
    fn test_zero_charge_update() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let rho = Felt::from(7u64);

        let c = PedersenCommitment::commit(balance, &blinding);
        let anon = c.rerandomize(&rho);

        let blind_delta = Felt::from(5u64);
        let updated = PedersenCommitment::server_update(&anon.point, 0, &blind_delta);

        let expected_blinding = blinding + rho + blind_delta;
        assert!(updated.verify_opening(balance, &expected_blinding));
    }

    #[test]
    fn curve_order_constant_is_group_order() {
        // n * P == identity for any group element confirms CURVE_ORDER_HEX is
        // the true Stark curve order.
        let n = Felt::from_hex_unchecked(CURVE_ORDER_HEX);
        assert_eq!(scalar_mul(&G_BALANCE, &n), ProjectivePoint::identity());
        assert_eq!(scalar_mul(&H_BLIND, &n), ProjectivePoint::identity());
    }

    #[test]
    fn blinding_accumulation_stays_consistent_past_field_prime() {
        // Two blinding contributions, each below the base-field prime p, whose
        // integer sum exceeds p — the case that made `Felt` addition wrap and
        // diverge from the committed point across multiple requests.
        let big = Felt::from_hex_unchecked(
            "0700000000000000000000000000000000000000000000000000000000000000",
        );
        let delta = Felt::from_hex_unchecked(
            "0700000000000000000000000000000000000000000000000000000000000000",
        );

        // Sanity: the naive base-field sum differs from the mod-n sum here.
        let felt_sum = big + delta;
        let mod_n_sum = add_blinding(&big, &delta);
        assert_ne!(
            felt_sum, mod_n_sum,
            "test inputs must actually cross the base-field prime"
        );

        let balance = 500u128;
        // Reference: commit then rerandomize, i.e. pure point arithmetic — this
        // is exactly what the server does homomorphically.
        let reference = PedersenCommitment::commit(balance, &big).rerandomize(&delta);

        // The mod-n accumulated blinding opens the same point.
        let via_accumulated = PedersenCommitment::commit(balance, &mod_n_sum);
        assert_eq!(via_accumulated.point, reference.point);
        assert!(reference.verify_opening(balance, &mod_n_sum));

        // The naive base-field sum does NOT open the committed point.
        let via_felt = PedersenCommitment::commit(balance, &felt_sum);
        assert_ne!(via_felt.point, reference.point);
    }
}
