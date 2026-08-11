//! Native zkAPI v2 primitives over the BN254 scalar field.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use zkapi_types::{Felt252, MERKLE_DEPTH};

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2.null";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
const DOMAIN_WITHDRAWAL: &[u8] = b"zkapi.v2.withdraw";
const DOMAIN_ANCHOR: &[u8] = b"zkapi.v2.anchor";
const DOMAIN_BLIND: &[u8] = b"zkapi.v2.blind";

fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );
        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds,
            ark,
            rate,
            1,
        )
    })
}

fn domain(label: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(label)
}

pub fn felt_to_field(value: &Felt252) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

pub fn field_to_felt(value: &Fr) -> Felt252 {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    Felt252(bytes)
}

pub fn hash_fields(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn hash_felts(inputs: &[Felt252]) -> Felt252 {
    let fields = inputs.iter().map(felt_to_field).collect::<Vec<_>>();
    field_to_felt(&hash_fields(&fields))
}

fn hash_domain(label: &[u8], inputs: &[Felt252]) -> Felt252 {
    let mut fields = Vec::with_capacity(inputs.len() + 1);
    fields.push(domain(label));
    fields.extend(inputs.iter().map(felt_to_field));
    field_to_felt(&hash_fields(&fields))
}

pub fn registration_commitment(secret: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_REG, &[*secret, Felt252::ZERO])
}

pub fn note_leaf(
    note_id: u32,
    registration: &Felt252,
    deposit_amount: u128,
    expiry: u64,
) -> Felt252 {
    hash_domain(
        DOMAIN_LEAF,
        &[
            Felt252::from_u64(note_id as u64),
            *registration,
            Felt252::from_u128(deposit_amount),
            Felt252::from_u64(expiry),
        ],
    )
}

pub fn merkle_node(left: &Felt252, right: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_NODE, &[*left, *right])
}

pub fn merkle_root(note_id: u32, leaf: &Felt252, siblings: &[Felt252; MERKLE_DEPTH]) -> Felt252 {
    let mut current = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            merkle_node(&current, sibling)
        } else {
            merkle_node(sibling, &current)
        };
    }
    current
}

pub fn zero_hashes() -> [Felt252; MERKLE_DEPTH + 1] {
    let mut values = [Felt252::ZERO; MERKLE_DEPTH + 1];
    for level in 1..=MERKLE_DEPTH {
        values[level] = merkle_node(&values[level - 1], &values[level - 1]);
    }
    values
}

pub fn nullifier(secret: &Felt252, anchor: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_NULLIFIER, &[*secret, *anchor])
}

pub fn authorization_tag(nullifier: &Felt252, request_context: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_AUTHORIZATION, &[*nullifier, *request_context])
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    commitment_x: &Felt252,
    commitment_y: &Felt252,
    anchor: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_STATE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *commitment_x,
            *commitment_y,
            *anchor,
        ],
    )
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    withdrawal_nullifier: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_CLEARANCE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *withdrawal_nullifier,
        ],
    )
}

pub fn withdrawal_tag(
    nullifier: &Felt252,
    destination: &Felt252,
    final_balance: u128,
    has_clearance: bool,
) -> Felt252 {
    hash_domain(
        DOMAIN_WITHDRAWAL,
        &[
            *nullifier,
            *destination,
            Felt252::from_u128(final_balance),
            Felt252::from_u64(has_clearance as u64),
        ],
    )
}

pub fn next_anchor(
    server_randomness: &Felt252,
    request_nullifier: &Felt252,
    commitment_x: &Felt252,
    commitment_y: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_ANCHOR,
        &[
            *server_randomness,
            *request_nullifier,
            *commitment_x,
            *commitment_y,
        ],
    )
}

pub fn blind_delta(server_randomness: &Felt252, request_nullifier: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_BLIND, &[*server_randomness, *request_nullifier])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_membership_round_trip() {
        let secret = Felt252::from_u64(42);
        let registration = registration_commitment(&secret);
        let leaf = note_leaf(0, &registration, 5_000_000, 4_000_000_000);
        let siblings = [Felt252::ZERO; MERKLE_DEPTH];
        assert_eq!(
            merkle_root(0, &leaf, &siblings),
            merkle_root(0, &leaf, &siblings)
        );
    }
}
