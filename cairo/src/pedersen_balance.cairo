// Pedersen balance commitment on the Stark curve.
//
// E(B, r) = B * G_balance + r * H_blind
//
// NON-PQ EXCEPTION: This is the one accepted non-post-quantum component
// in zkAPI v1.  Homomorphic addition and rerandomization require an
// elliptic-curve commitment, which is inherently not post-quantum.
// This exception is explicitly documented per the protocol specification.
//
// G_BALANCE and H_BLIND are fixed independent generators derived by the Rust
// reference implementation from the labels "zkapi.bal.g" and "zkapi.bal.h".
// These exact affine coordinates are mirrored here so Cairo and Rust commit to
// the same curve points.
//
// This module intentionally avoids `core::ec`. Scarb/Stwo currently routes
// that API through the `ecdsa_builtin`, which the Stwo adapter does not support.
// The small affine formulas below keep the proof statement in ordinary field
// arithmetic so request proofs can be executed by Stwo.

use core::felt252_div;
use core::num::traits::DivRem;
use core::zeroable::NonZero;

// ---------------------------------------------------------------------------
// Generator points
// ---------------------------------------------------------------------------

// G_balance generator coordinates.
const G_BALANCE_X: felt252 = 0x2e60e3230fe061dbebac8fd2cfa503e4eb92783aeb5fd6fb931a66ee277e4d3;
const G_BALANCE_Y: felt252 = 0x39289536a4fb4c04778f51eed313db47730cf86d342fd3f80f27bed1c2febac;

// H_blind generator coordinates.
const H_BLIND_X: felt252 = 0x9ed31288dc3e29f8759144b455aa05f39eee1a947e92fc1a9d71d15ed49faa;
const H_BLIND_Y: felt252 = 0x73853a56a47d4dbeaf5c18ca78fbf64f414d5fccefaac0227d5c2654d2ca9b4;

// Order of the Stark curve cyclic group. Blinding factors are scalars in
// Z/nZ, not elements of the Stark base field.
const EC_ORDER: u256 = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f_u256;

/// Add two canonical blinding scalars modulo the Stark curve order.
///
/// Converting to u256 before addition preserves the carry that felt252
/// addition would otherwise discard modulo the base-field prime.
pub fn add_blinding(a: felt252, b: felt252) -> felt252 {
    let sum: u256 = a.into() + b.into();
    let reduced = if sum >= EC_ORDER {
        sum - EC_ORDER
    } else {
        sum
    };
    reduced.try_into().expect('blinding exceeds felt')
}

fn point_double(is_inf: bool, x: felt252, y: felt252) -> (bool, felt252, felt252) {
    if is_inf {
        return (true, 0, 0);
    }
    if y == 0 {
        return (true, 0, 0);
    }

    // Stark curve: y^2 = x^3 + x + beta.
    let denominator: NonZero<felt252> = (2 * y).try_into().expect('zero denominator');
    let slope = felt252_div((3 * x * x) + 1, denominator);
    let x3 = (slope * slope) - x - x;
    let y3 = (slope * (x - x3)) - y;
    (false, x3, y3)
}

fn point_add(
    p_inf: bool, px: felt252, py: felt252, q_inf: bool, qx: felt252, qy: felt252,
) -> (bool, felt252, felt252) {
    if p_inf {
        return (q_inf, qx, qy);
    }
    if q_inf {
        return (p_inf, px, py);
    }
    if px == qx {
        if py == qy {
            return point_double(p_inf, px, py);
        }
        return (true, 0, 0);
    }

    let denominator: NonZero<felt252> = (qx - px).try_into().expect('zero denominator');
    let slope = felt252_div(qy - py, denominator);
    let x3 = (slope * slope) - px - qx;
    let y3 = (slope * (px - x3)) - py;
    (false, x3, y3)
}

fn scalar_mul(point_x: felt252, point_y: felt252, scalar: felt252) -> (bool, felt252, felt252) {
    let mut result_inf = true;
    let mut result_x = 0;
    let mut result_y = 0;
    let mut addend_inf = false;
    let mut addend_x = point_x;
    let mut addend_y = point_y;
    let mut remaining: u256 = scalar.into();
    let two: NonZero<u256> = 2_u256.try_into().unwrap();
    let mut i: u32 = 0;

    while i < 252 {
        let (next_remaining, bit) = DivRem::div_rem(remaining, two);
        if bit == 1_u256 {
            let (sum_inf, sum_x, sum_y) = point_add(
                result_inf, result_x, result_y, addend_inf, addend_x, addend_y,
            );
            result_inf = sum_inf;
            result_x = sum_x;
            result_y = sum_y;
        }

        let (double_inf, double_x, double_y) = point_double(addend_inf, addend_x, addend_y);
        addend_inf = double_inf;
        addend_x = double_x;
        addend_y = double_y;
        remaining = next_remaining;
        i += 1;
    }

    (result_inf, result_x, result_y)
}

/// Compute the Pedersen balance commitment E(balance, blinding).
///
/// Returns the commitment as an (x, y) pair.
/// Panics if the resulting point is the point at infinity.
pub fn compute_commitment(balance: felt252, blinding: felt252) -> (felt252, felt252) {
    let (g_inf, g_x, g_y) = scalar_mul(G_BALANCE_X, G_BALANCE_Y, balance);
    let (h_inf, h_x, h_y) = scalar_mul(H_BLIND_X, H_BLIND_Y, blinding);
    let (result_inf, result_x, result_y) = point_add(g_inf, g_x, g_y, h_inf, h_x, h_y);
    assert(!result_inf, 'commitment is infinity');
    (result_x, result_y)
}

/// Verify that the given point (px, py) equals the commitment
/// E(balance, blinding) = balance * G_balance + blinding * H_blind.
pub fn verify_commitment_opening(px: felt252, py: felt252, balance: felt252, blinding: felt252) {
    let (cx, cy) = compute_commitment(balance, blinding);
    assert(px == cx, 'commitment x mismatch');
    assert(py == cy, 'commitment y mismatch');
}

#[cfg(test)]
mod tests {
    use super::{EC_ORDER, add_blinding, compute_commitment, verify_commitment_opening};

    #[test]
    fn test_blinding_addition_reduces_mod_curve_order() {
        let n_minus_one: felt252 = (EC_ORDER - 1_u256).try_into().unwrap();
        assert(add_blinding(n_minus_one, 2) == 1, 'wrong scalar reduction');
    }

    #[test]
    fn test_commitment_matches_rust_vector() {
        let (x, y) = compute_commitment(1000, 42);
        assert(
            x == 0x77bd464e41fd97fc8eb7b2cf070fc6f3d7587707446b027e0c6b60a29a05eae,
            'unexpected commitment x',
        );
        assert(
            y == 0x23fd385119e903dd48d501552b1fb84e6e61a4685fe4d7ee4a6b71063a05611,
            'unexpected commitment y',
        );
    }

    #[test]
    fn test_verify_opening_roundtrip() {
        let (x, y) = compute_commitment(77, 5);
        verify_commitment_opening(x, y, 77, 5);
    }
}
