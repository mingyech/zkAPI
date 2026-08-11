// WOTS+ one-time signature verification built on Poseidon.
//
// Parameters (from spec section 4.9):
//   w = 16  (base-16 digits)
//   n = 248 bits (one felt252 message digest)
//   len1 = 62  (ceil(248 / 4))
//   len2 = 3
//   len  = 65

use core::num::traits::DivRem;
use core::poseidon::poseidon_hash_span;
use core::zeroable::NonZero;
use zkapi_cairo::constants::WOTS_W;
use zkapi_cairo::domains::{DOMAIN_XMSS_CHAIN, DOMAIN_XMSS_LEAF};

// ---------------------------------------------------------------------------
// Chain function
// ---------------------------------------------------------------------------

/// One step of the WOTS+ hash chain.
/// chain_step(value, step) = Poseidon(DOMAIN_XMSS_CHAIN, value, step)
pub fn chain_step(value: felt252, step: felt252) -> felt252 {
    poseidon_hash_span(array![DOMAIN_XMSS_CHAIN, value, step].span())
}

/// Apply the chain function `steps` times starting from `value` at position
/// `start`.  Each iteration hashes the current value with its absolute
/// chain index (start + i).
pub fn chain(value: felt252, start: u32, steps: u32) -> felt252 {
    let mut current = value;
    let mut i: u32 = 0;
    while i < steps {
        let step_index: felt252 = (start + i).into();
        current = chain_step(current, step_index);
        i += 1;
    }
    current
}

// ---------------------------------------------------------------------------
// Message-to-base-w conversion
// ---------------------------------------------------------------------------

/// Extract base-16 digits from a 248-bit message digest (one felt252).
///
/// Returns an array of `WOTS_LEN` (65) values:
///   - indices 0..61  are the 62 base-16 digits of the message (MSB first)
///   - indices 62..64 are the 3 base-16 digits of the checksum
///
/// Each digit is in [0, 15].
pub fn message_to_base_w(message: felt252) -> Array<u32> {
    let mut digits: Array<u32> = array![];

    // Decompose message into 62 base-16 (4-bit) digits.
    // We work with u256 for bit manipulation.
    let msg_u256: u256 = message.into();
    let mut remaining = msg_u256;

    // Extract one base-16 digit per division, starting at the least
    // significant end. This is linear in the number of digits; rebuilding
    // 2^shift for every digit made the old implementation quadratic.
    let mut i: u32 = 0;
    let mut lsb_nibbles: Array<u32> = array![];
    let sixteen: NonZero<u256> = 16_u256.try_into().unwrap();
    while i < 62 {
        let (next_remaining, digit) = DivRem::div_rem(remaining, sixteen);
        lsb_nibbles.append(digit.try_into().unwrap());
        remaining = next_remaining;
        i += 1;
    }

    // WOTS consumes digits most-significant first. Build the output and its
    // checksum in one pass instead of copying the digits twice more.
    let mut checksum: u32 = 0;
    let mut i: u32 = 0;
    while i < 62 {
        let digit = *lsb_nibbles.at(61 - i);
        digits.append(digit);
        checksum += (WOTS_W - 1) - digit;
        i += 1;
    }

    // Decompose checksum into WOTS_LEN2 = 3 base-16 digits (MSB first).
    // Maximum checksum = 62 * 15 = 930, which fits in 3 hex digits (0x3A2).
    let cs_digit_2: u32 = checksum / 256; // 16^2
    let cs_digit_1: u32 = (checksum % 256) / 16;
    let cs_digit_0: u32 = checksum % 16;

    // Append checksum digits.
    digits.append(cs_digit_2);
    digits.append(cs_digit_1);
    digits.append(cs_digit_0);

    digits
}

// ---------------------------------------------------------------------------
// WOTS+ verification
// ---------------------------------------------------------------------------

/// Given a WOTS+ signature and message digest, recover the public key values
/// by chaining each signature element from its digit position to w-1.
///
/// `wots_sig` must have exactly WOTS_LEN (65) elements.
/// Returns an array of 65 recovered public key chain endpoints.
pub fn wots_verify(wots_sig: Span<felt252>, message: felt252) -> Array<felt252> {
    assert(wots_sig.len() == 65, 'invalid wots sig len');

    let digits = message_to_base_w(message);
    let mut pk_values: Array<felt252> = array![];

    let mut i: u32 = 0;
    while i < 65 {
        let digit = *digits.at(i);
        // Chain from position digit to position (w - 1), i.e. (w - 1 - digit) steps.
        let steps = WOTS_W - 1 - digit;
        let recovered = chain(*wots_sig.at(i), digit, steps);
        pk_values.append(recovered);
        i += 1;
    }

    pk_values
}

/// Hash recovered public key values into a single leaf value.
/// leaf = Poseidon(DOMAIN_XMSS_LEAF, pk[0], pk[1], ..., pk[64])
pub fn wots_pk_to_leaf(pk_values: Span<felt252>) -> felt252 {
    assert(pk_values.len() == 65, 'invalid pk values len');

    let mut preimage: Array<felt252> = array![DOMAIN_XMSS_LEAF];
    let mut i: u32 = 0;
    while i < 65 {
        preimage.append(*pk_values.at(i));
        i += 1;
    }
    poseidon_hash_span(preimage.span())
}
