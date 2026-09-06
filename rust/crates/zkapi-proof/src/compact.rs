//! Stable native interface for zkAPI v2 Groth16 proofs and curve operations.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as EdwardsScalarField};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_types::wire::{CurvePointWire, Groth16ProofWire, ProofBackendWire};
use zkapi_types::{
    Felt252, RequestPublicInputsV2, SchnorrSignature, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

use crate::groth16::{
    balance_blinding_generator, prove_request, prove_withdrawal, request_setup,
    rerandomize_commitment, verify_request, verify_state_signature, verify_withdrawal,
    withdrawal_setup, RequestCircuit, RequestPublic, RequestWitness, StateSignature,
    StateSigningKey, WithdrawalCircuit, WithdrawalPublic, WithdrawalWitness,
};

pub const REQUEST_PROVING_KEY_FILE: &str = "request.pk";
pub const REQUEST_VERIFYING_KEY_FILE: &str = "request.vk";
pub const WITHDRAWAL_PROVING_KEY_FILE: &str = "withdrawal.pk";
pub const WITHDRAWAL_VERIFYING_KEY_FILE: &str = "withdrawal.vk";
pub const SETUP_MANIFEST_FILE: &str = "manifest.json";
pub const SOLIDITY_POSEIDON_FILE: &str = "Bn254Poseidon.sol";
pub const SOLIDITY_VERIFIER_FILE: &str = "Groth16ProofAdapter.sol";

#[derive(Serialize)]
struct SetupManifest {
    protocol_version: u16,
    proof_backend: &'static str,
    request: VerifyingKeyManifest,
    withdrawal: VerifyingKeyManifest,
    poseidon: PoseidonManifest,
}

#[derive(Serialize)]
struct VerifyingKeyManifest {
    alpha_g1: [String; 2],
    beta_g2: [[String; 2]; 2],
    gamma_g2: [[String; 2]; 2],
    delta_g2: [[String; 2]; 2],
    ic: Vec<[String; 2]>,
}

#[derive(Serialize)]
struct PoseidonManifest {
    field_modulus: String,
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
    round_constants: Vec<String>,
    mds: Vec<String>,
    test_hash3: String,
    test_hash5: String,
}

#[derive(Clone, Debug)]
pub struct RequestWitnessData {
    pub secret: Felt252,
    pub request_context: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: Felt252,
    pub rerandomization: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
}

#[derive(Clone, Debug)]
pub struct WithdrawalWitnessData {
    pub secret: Felt252,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub final_blinding: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
    pub clearance_signature: Option<SchnorrSignature>,
}

pub struct RequestProver {
    key: ProvingKey<Bn254>,
}

impl RequestProver {
    /// Decode the canonical proving-key bytes supplied by the caller.
    /// Browser clients use this because WebAssembly has no native filesystem.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            key: decode_compressed(bytes).context("decode request proving key")?,
        })
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory.as_ref().join(REQUEST_PROVING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn prove(
        &self,
        public: &RequestPublicInputsV2,
        witness: RequestWitnessData,
    ) -> Result<Groth16ProofWire> {
        let circuit = RequestCircuit {
            public: request_public_from_wire(public)?,
            witness: RequestWitness {
                secret: field(&witness.secret),
                request_context: field(&witness.request_context),
                note_id: witness.note_id,
                deposit_amount: witness.deposit_amount,
                expiry: witness.expiry,
                merkle_siblings: witness.merkle_siblings.map(|value| field(&value)),
                current_balance: witness.current_balance,
                current_blinding: scalar(&witness.current_blinding),
                rerandomization: scalar(&witness.rerandomization),
                current_anchor: field(&witness.current_anchor),
                is_genesis: witness.is_genesis,
                state_signature: signature_from_wire(
                    witness
                        .state_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
            },
        };
        let proof = prove_request(&self.key, circuit, &mut OsRng)
            .map_err(|error| anyhow!("request proving failed: {error}"))?;
        proof_to_wire(&proof)
    }
}

pub struct RequestVerifier {
    key: VerifyingKey<Bn254>,
}

impl RequestVerifier {
    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            key: read_compressed(directory.as_ref().join(REQUEST_VERIFYING_KEY_FILE))?,
        })
    }

    pub fn verify(&self, public: &RequestPublicInputsV2, proof: &Groth16ProofWire) -> Result<bool> {
        ensure_backend(proof)?;
        let proof = proof_from_wire(proof)?;
        verify_request(&self.key, &request_public_from_wire(public)?, &proof)
            .map_err(|error| anyhow!("request verification failed: {error}"))
    }
}

pub struct WithdrawalProver {
    key: ProvingKey<Bn254>,
}

impl WithdrawalProver {
    /// Decode the canonical proving-key bytes supplied by the caller.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            key: decode_compressed(bytes).context("decode withdrawal proving key")?,
        })
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory.as_ref().join(WITHDRAWAL_PROVING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn prove(
        &self,
        public: &WithdrawalPublicInputsV2,
        witness: WithdrawalWitnessData,
    ) -> Result<Groth16ProofWire> {
        let circuit = WithdrawalCircuit {
            public: withdrawal_public_from_wire(public)?,
            witness: WithdrawalWitness {
                secret: field(&witness.secret),
                deposit_amount: witness.deposit_amount,
                expiry: witness.expiry,
                merkle_siblings: witness.merkle_siblings.map(|value| field(&value)),
                final_blinding: scalar(&witness.final_blinding),
                current_anchor: field(&witness.current_anchor),
                is_genesis: witness.is_genesis,
                state_signature: signature_from_wire(
                    witness
                        .state_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
                clearance_signature: signature_from_wire(
                    witness
                        .clearance_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
            },
        };
        let proof = prove_withdrawal(&self.key, circuit, &mut OsRng)
            .map_err(|error| anyhow!("withdrawal proving failed: {error}"))?;
        proof_to_wire(&proof)
    }
}

pub struct WithdrawalVerifier {
    key: VerifyingKey<Bn254>,
}

impl WithdrawalVerifier {
    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            key: read_compressed(directory.as_ref().join(WITHDRAWAL_VERIFYING_KEY_FILE))?,
        })
    }

    pub fn verify(
        &self,
        public: &WithdrawalPublicInputsV2,
        proof: &Groth16ProofWire,
    ) -> Result<bool> {
        ensure_backend(proof)?;
        let proof = proof_from_wire(proof)?;
        verify_withdrawal(&self.key, &withdrawal_public_from_wire(public)?, &proof)
            .map_err(|error| anyhow!("withdrawal verification failed: {error}"))
    }
}

#[derive(Clone)]
pub struct CompactSigner {
    key: StateSigningKey,
}

impl CompactSigner {
    pub fn from_seed(seed: &Felt252) -> Self {
        Self {
            key: StateSigningKey::from_secret(scalar(seed)),
        }
    }

    pub fn public_key(&self) -> CurvePointWire {
        point_to_wire(self.key.public)
    }

    pub fn sign(&self, message: &Felt252) -> SchnorrSignature {
        signature_to_wire(self.key.sign(field(message), &mut OsRng))
    }

    pub fn verify(&self, message: &Felt252, signature: &SchnorrSignature) -> Result<bool> {
        Ok(verify_state_signature(
            self.key.public,
            field(message),
            signature_from_wire(*signature)?,
        ))
    }
}

pub fn setup(directory: impl AsRef<Path>) -> Result<()> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)
        .with_context(|| format!("create setup directory {}", directory.display()))?;
    let template_signer = CompactSigner::from_seed(&Felt252::ONE);
    let state_key = point_from_wire(&template_signer.public_key())?;
    let identity = EdwardsAffine::zero();
    let empty_signature = StateSignature {
        r: identity,
        s: EdwardsScalarField::from(0u64),
    };

    let request_template = RequestCircuit {
        public: RequestPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            active_root: Fr::from(1u64),
            state_signing_key: state_key,
            request_time: 1,
            solvency_bound: 0,
            request_nullifier: Fr::from(1u64),
            authorization_tag: Fr::from(1u64),
            anonymous_commitment: EdwardsProjective::generator().into_affine(),
        },
        witness: RequestWitness {
            secret: Fr::from(1u64),
            request_context: Fr::from(1u64),
            note_id: 0,
            deposit_amount: 0,
            expiry: 1,
            merkle_siblings: [Fr::from(0u64); MERKLE_DEPTH],
            current_balance: 0,
            current_blinding: EdwardsScalarField::from(0u64),
            rerandomization: EdwardsScalarField::from(0u64),
            current_anchor: Fr::from(1u64),
            is_genesis: true,
            state_signature: empty_signature,
        },
    };
    let (request_pk, request_vk) = request_setup(request_template, &mut OsRng)
        .map_err(|error| anyhow!("request setup failed: {error}"))?;
    write_compressed(directory.join(REQUEST_PROVING_KEY_FILE), &request_pk)?;
    write_compressed(directory.join(REQUEST_VERIFYING_KEY_FILE), &request_vk)?;

    let withdrawal_template = WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            active_root: Fr::from(1u64),
            state_signing_key: state_key,
            clearance_signing_key: state_key,
            note_id: 0,
            final_balance: 0,
            destination: Fr::from(1u64),
            withdrawal_nullifier: Fr::from(1u64),
            has_clearance: false,
            withdrawal_tag: Fr::from(1u64),
        },
        witness: WithdrawalWitness {
            secret: Fr::from(1u64),
            deposit_amount: 0,
            expiry: 1,
            merkle_siblings: [Fr::from(0u64); MERKLE_DEPTH],
            final_blinding: EdwardsScalarField::from(0u64),
            current_anchor: Fr::from(1u64),
            is_genesis: true,
            state_signature: empty_signature,
            clearance_signature: empty_signature,
        },
    };
    let (withdrawal_pk, withdrawal_vk) = withdrawal_setup(withdrawal_template, &mut OsRng)
        .map_err(|error| anyhow!("withdrawal setup failed: {error}"))?;
    write_compressed(directory.join(WITHDRAWAL_PROVING_KEY_FILE), &withdrawal_pk)?;
    write_compressed(
        directory.join(WITHDRAWAL_VERIFYING_KEY_FILE),
        &withdrawal_vk,
    )?;
    let manifest = SetupManifest {
        protocol_version: 2,
        proof_backend: "groth16_bn254",
        request: verifying_key_manifest(&request_vk),
        withdrawal: verifying_key_manifest(&withdrawal_vk),
        poseidon: poseidon_manifest(),
    };
    fs::write(
        directory.join(SETUP_MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).context("encode setup manifest")?,
    )
    .context("write setup manifest")?;
    fs::write(
        directory.join(SOLIDITY_POSEIDON_FILE),
        poseidon_solidity_source(),
    )
    .context("write Solidity Poseidon library")?;
    fs::write(
        directory.join(SOLIDITY_VERIFIER_FILE),
        groth16_solidity_source(&request_vk, &withdrawal_vk),
    )
    .context("write Solidity Groth16 verifier")?;
    Ok(())
}

pub fn random_field() -> Felt252 {
    felt(&Fr::rand(&mut OsRng))
}

pub fn random_scalar() -> Felt252 {
    scalar_to_felt(&EdwardsScalarField::rand(&mut OsRng))
}

pub fn balance_commitment(balance: u128, blinding: &Felt252) -> CurvePointWire {
    let point = EdwardsProjective::generator()
        .mul_bigint(EdwardsScalarField::from(balance).into_bigint())
        + balance_blinding_generator().mul_bigint(scalar(blinding).into_bigint());
    point_to_wire(point.into_affine())
}

pub fn rerandomize(
    commitment: &CurvePointWire,
    rerandomization: &Felt252,
) -> Result<CurvePointWire> {
    Ok(point_to_wire(
        rerandomize_commitment(
            point_from_wire(commitment)?.into_group(),
            scalar(rerandomization),
        )
        .into_affine(),
    ))
}

pub fn add_blindings(left: &Felt252, right: &Felt252) -> Felt252 {
    scalar_to_felt(&(scalar(left) + scalar(right)))
}

pub fn server_update(
    anonymous: &CurvePointWire,
    charge: u128,
    blind_delta: &Felt252,
) -> Result<CurvePointWire> {
    let point = point_from_wire(anonymous)?.into_group()
        - EdwardsProjective::generator().mul_bigint(EdwardsScalarField::from(charge).into_bigint())
        + balance_blinding_generator().mul_bigint(scalar(blind_delta).into_bigint());
    Ok(point_to_wire(point.into_affine()))
}

pub fn verify_signature(
    public_key: &CurvePointWire,
    message: &Felt252,
    signature: &SchnorrSignature,
) -> Result<bool> {
    Ok(verify_state_signature(
        point_from_wire(public_key)?,
        field(message),
        signature_from_wire(*signature)?,
    ))
}

fn request_public_from_wire(public: &RequestPublicInputsV2) -> Result<RequestPublic> {
    Ok(RequestPublic {
        protocol_version: public.protocol_version,
        chain_id: public.chain_id,
        contract_address: field(&public.contract_address),
        active_root: field(&public.active_root),
        state_signing_key: point_from_wire(&CurvePointWire {
            x: public.state_signing_key_x,
            y: public.state_signing_key_y,
        })?,
        request_time: public.request_time,
        solvency_bound: public.solvency_bound,
        request_nullifier: field(&public.request_nullifier),
        authorization_tag: field(&public.authorization_tag),
        anonymous_commitment: point_from_wire(&CurvePointWire {
            x: public.anonymous_commitment_x,
            y: public.anonymous_commitment_y,
        })?,
    })
}

fn withdrawal_public_from_wire(public: &WithdrawalPublicInputsV2) -> Result<WithdrawalPublic> {
    Ok(WithdrawalPublic {
        protocol_version: public.protocol_version,
        chain_id: public.chain_id,
        contract_address: field(&public.contract_address),
        active_root: field(&public.active_root),
        state_signing_key: point_from_wire(&CurvePointWire {
            x: public.state_signing_key_x,
            y: public.state_signing_key_y,
        })?,
        clearance_signing_key: point_from_wire(&CurvePointWire {
            x: public.clearance_signing_key_x,
            y: public.clearance_signing_key_y,
        })?,
        note_id: public.note_id,
        final_balance: public.final_balance,
        destination: field(&public.destination_field()),
        withdrawal_nullifier: field(&public.withdrawal_nullifier),
        has_clearance: public.has_clearance,
        withdrawal_tag: field(&public.withdrawal_tag),
    })
}

fn ensure_backend(proof: &Groth16ProofWire) -> Result<()> {
    if proof.backend != ProofBackendWire::Groth16Bn254 {
        return Err(anyhow!("expected groth16_bn254 proof backend"));
    }
    Ok(())
}

fn proof_to_wire(proof: &Proof<Bn254>) -> Result<Groth16ProofWire> {
    let mut bytes = Vec::with_capacity(256);
    for coordinate in [
        proof.a.x,
        proof.a.y,
        proof.b.x.c0,
        proof.b.x.c1,
        proof.b.y.c0,
        proof.b.y.c1,
        proof.c.x,
        proof.c.y,
    ] {
        bytes.extend_from_slice(&prime_field_bytes(&coordinate));
    }
    Ok(Groth16ProofWire {
        backend: ProofBackendWire::Groth16Bn254,
        proof: base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

fn proof_from_wire(proof: &Groth16ProofWire) -> Result<Proof<Bn254>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.proof)
        .context("decode Groth16 proof base64")?;
    if bytes.len() != 256 {
        return Err(anyhow!(
            "Groth16 proof must contain eight 32-byte coordinates"
        ));
    }
    let coordinates = bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|coordinate| canonical_fq(coordinate))
        .collect::<Result<Vec<_>>>()?;
    let a = G1Affine::new_unchecked(coordinates[0], coordinates[1]);
    let b = G2Affine::new_unchecked(
        Fq2::new(coordinates[2], coordinates[3]),
        Fq2::new(coordinates[4], coordinates[5]),
    );
    let c = G1Affine::new_unchecked(coordinates[6], coordinates[7]);
    if !a.is_on_curve()
        || !a.is_in_correct_subgroup_assuming_on_curve()
        || !b.is_on_curve()
        || !b.is_in_correct_subgroup_assuming_on_curve()
        || !c.is_on_curve()
        || !c.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(anyhow!("Groth16 proof contains an invalid curve point"));
    }
    Ok(Proof { a, b, c })
}

fn canonical_fq(bytes: &[u8]) -> Result<Fq> {
    let value = Fq::from_be_bytes_mod_order(bytes);
    if prime_field_bytes(&value).as_slice() != bytes {
        return Err(anyhow!("non-canonical BN254 base-field coordinate"));
    }
    Ok(value)
}

fn prime_field_bytes<F: PrimeField>(value: &F) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    bytes
}

fn signature_from_wire(signature: SchnorrSignature) -> Result<StateSignature> {
    Ok(StateSignature {
        r: point_from_wire(&CurvePointWire {
            x: signature.r_x,
            y: signature.r_y,
        })?,
        s: scalar(&signature.s),
    })
}

fn signature_to_wire(signature: StateSignature) -> SchnorrSignature {
    let point = point_to_wire(signature.r);
    SchnorrSignature {
        r_x: point.x,
        r_y: point.y,
        s: scalar_to_felt(&signature.s),
    }
}

fn point_from_wire(point: &CurvePointWire) -> Result<EdwardsAffine> {
    let point = EdwardsAffine::new_unchecked(field(&point.x), field(&point.y));
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("invalid Baby-JubJub point"));
    }
    Ok(point)
}

fn point_to_wire(point: EdwardsAffine) -> CurvePointWire {
    CurvePointWire {
        x: felt(&point.x),
        y: felt(&point.y),
    }
}

fn field(value: &Felt252) -> Fr {
    core::felt_to_field(value)
}

fn felt(value: &Fr) -> Felt252 {
    core::field_to_felt(value)
}

fn scalar(value: &Felt252) -> EdwardsScalarField {
    EdwardsScalarField::from_be_bytes_mod_order(value.as_bytes())
}

fn scalar_to_felt(value: &EdwardsScalarField) -> Felt252 {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    Felt252(bytes)
}

fn read_compressed<T: CanonicalDeserialize>(path: PathBuf) -> Result<T> {
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    decode_compressed(&bytes).with_context(|| format!("decode {}", path.display()))
}

fn decode_compressed<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    T::deserialize_compressed(bytes)
        .map_err(|error| anyhow!("deserialize compressed value: {error}"))
}

fn write_compressed<T: CanonicalSerialize>(path: PathBuf, value: &T) -> Result<()> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .with_context(|| format!("encode {}", path.display()))?;
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

fn verifying_key_manifest(key: &VerifyingKey<Bn254>) -> VerifyingKeyManifest {
    VerifyingKeyManifest {
        alpha_g1: g1_manifest(&key.alpha_g1),
        beta_g2: g2_manifest(&key.beta_g2),
        gamma_g2: g2_manifest(&key.gamma_g2),
        delta_g2: g2_manifest(&key.delta_g2),
        ic: key.gamma_abc_g1.iter().map(g1_manifest).collect(),
    }
}

fn poseidon_manifest() -> PoseidonManifest {
    let config = crate::groth16::poseidon_config();
    PoseidonManifest {
        field_modulus: zkapi_types::FIELD_MODULUS_HEX.to_string(),
        full_rounds: config.full_rounds,
        partial_rounds: config.partial_rounds,
        alpha: config.alpha,
        rate: config.rate,
        capacity: config.capacity,
        round_constants: config.ark.iter().flatten().map(field_hex).collect(),
        mds: config.mds.iter().flatten().map(field_hex).collect(),
        test_hash3: field_hex(&crate::groth16::poseidon_hash(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ])),
        test_hash5: field_hex(&crate::groth16::poseidon_hash(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ])),
    }
}

fn poseidon_solidity_source() -> String {
    let config = crate::groth16::poseidon_config();
    let round_constants = config
        .ark
        .iter()
        .flatten()
        .map(|value| hex::encode(prime_field_bytes(value)))
        .collect::<String>();
    let mds = config
        .mds
        .iter()
        .flatten()
        .map(field_hex)
        .collect::<Vec<_>>();
    let mut source = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Bn254Poseidon
/// @notice Poseidon over the BN254 scalar field, generated from zkAPI v2's arkworks parameters.
/// @dev Width 3, rate 2, x^5 S-box, 8 full rounds, and 57 partial rounds.
library Bn254Poseidon {
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes internal constant ROUND_CONSTANTS = hex"__ROUND_CONSTANTS__";

    function hash3(uint256 a, uint256 b, uint256 c) public pure returns (uint256 result) {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") { freeMemoryPointer := mload(0x40) }
        bytes memory constants = ROUND_CONSTANTS;
        result = _hash3(a, b, c, constants);
        assembly ("memory-safe") { mstore(0x40, freeMemoryPointer) }
    }

    function hash5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e)
        public pure returns (uint256 result)
    {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") { freeMemoryPointer := mload(0x40) }
        bytes memory constants = ROUND_CONSTANTS;
        uint256[3] memory state;
        state[1] = a;
        state[2] = b;
        _permute(state, constants);
        state[1] = addmod(state[1], c, FIELD_MODULUS);
        state[2] = addmod(state[2], d, FIELD_MODULUS);
        _permute(state, constants);
        state[1] = addmod(state[1], e, FIELD_MODULUS);
        _permute(state, constants);
        result = state[1];
        assembly ("memory-safe") { mstore(0x40, freeMemoryPointer) }
    }

    function hash3PairPath32(
        uint256 domain,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings
    ) public pure returns (uint256 oldRoot, uint256 newRoot) {
        uint256 freeMemoryPointer;
        assembly ("memory-safe") { freeMemoryPointer := mload(0x40) }
        bytes memory constants = ROUND_CONSTANTS;
        oldRoot = oldLeaf;
        newRoot = newLeaf;
        for (uint256 level = 0; level < 32;) {
            uint256 sibling = siblings[level];
            if (((index >> level) & 1) == 0) {
                oldRoot = _hash3(domain, oldRoot, sibling, constants);
                newRoot = _hash3(domain, newRoot, sibling, constants);
            } else {
                oldRoot = _hash3(domain, sibling, oldRoot, constants);
                newRoot = _hash3(domain, sibling, newRoot, constants);
            }
            unchecked { ++level; }
        }
        assembly ("memory-safe") { mstore(0x40, freeMemoryPointer) }
    }

    function _hash3(uint256 a, uint256 b, uint256 c, bytes memory constants)
        private pure returns (uint256 result)
    {
        uint256[3] memory state;
        state[1] = a;
        state[2] = b;
        _permute(state, constants);
        state[1] = addmod(state[1], c, FIELD_MODULUS);
        _permute(state, constants);
        result = state[1];
    }

    function _permute(uint256[3] memory state, bytes memory constants) private pure {
        uint256 round;
        for (; round < 4;) {
            _round(state, constants, round, true);
            unchecked { ++round; }
        }
        for (; round < 61;) {
            _round(state, constants, round, false);
            unchecked { ++round; }
        }
        for (; round < 65;) {
            _round(state, constants, round, true);
            unchecked { ++round; }
        }
    }

    function _round(uint256[3] memory state, bytes memory constants, uint256 round, bool full)
        private pure
    {
        uint256 offset = round * 3;
        state[0] = addmod(state[0], _constant(constants, offset), FIELD_MODULUS);
        state[1] = addmod(state[1], _constant(constants, offset + 1), FIELD_MODULUS);
        state[2] = addmod(state[2], _constant(constants, offset + 2), FIELD_MODULUS);
        state[0] = _pow5(state[0]);
        if (full) {
            state[1] = _pow5(state[1]);
            state[2] = _pow5(state[2]);
        }
        uint256 x = state[0];
        uint256 y = state[1];
        uint256 z = state[2];
        state[0] = addmod(addmod(mulmod(x, __M0__, FIELD_MODULUS), mulmod(y, __M1__, FIELD_MODULUS), FIELD_MODULUS), mulmod(z, __M2__, FIELD_MODULUS), FIELD_MODULUS);
        state[1] = addmod(addmod(mulmod(x, __M3__, FIELD_MODULUS), mulmod(y, __M4__, FIELD_MODULUS), FIELD_MODULUS), mulmod(z, __M5__, FIELD_MODULUS), FIELD_MODULUS);
        state[2] = addmod(addmod(mulmod(x, __M6__, FIELD_MODULUS), mulmod(y, __M7__, FIELD_MODULUS), FIELD_MODULUS), mulmod(z, __M8__, FIELD_MODULUS), FIELD_MODULUS);
    }

    function _pow5(uint256 value) private pure returns (uint256) {
        uint256 square = mulmod(value, value, FIELD_MODULUS);
        return mulmod(mulmod(square, square, FIELD_MODULUS), value, FIELD_MODULUS);
    }

    function _constant(bytes memory constants, uint256 index) private pure returns (uint256 value) {
        assembly ("memory-safe") { value := mload(add(add(constants, 0x20), mul(index, 0x20))) }
    }
}
"#
    .replace("__ROUND_CONSTANTS__", &round_constants);
    for (index, value) in mds.iter().enumerate() {
        source = source.replace(&format!("__M{index}__"), value);
    }
    source
}

fn groth16_solidity_source(
    request_key: &VerifyingKey<Bn254>,
    withdrawal_key: &VerifyingKey<Bn254>,
) -> String {
    let mut source = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice Circuit-specific zkAPI v2 verifier generated from the selected setup.
contract Groth16ProofAdapter is IZkApiProofAdapter {
    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point { uint256 x; uint256 y; }
    // Coordinates use arkworks order: c0 (real), then c1 (imaginary).
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct Proof { G1Point a; G2Point b; G1Point c; }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[12] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            uint256(inputs.requestTime),
            uint256(inputs.solvencyBound),
            inputs.requestNullifier,
            inputs.authorizationTag,
            inputs.anonymousCommitmentX,
            inputs.anonymousCommitmentY
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyRequest(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[14] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            inputs.clearanceSigningKeyX,
            inputs.clearanceSigningKeyY,
            uint256(inputs.noteId),
            uint256(inputs.finalBalance),
            uint256(uint160(inputs.destination)),
            inputs.withdrawalNullifier,
            inputs.hasClearance ? uint256(1) : uint256(0),
            inputs.withdrawalTag
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function _verifyRequest(uint256[12] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _requestIc(0);
        for (uint256 i = 0; i < 12; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_requestIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _requestAlpha(), _requestBeta(),
            accumulator, _requestGamma(),
            proof.c, _requestDelta()
        );
    }

    function _verifyWithdrawal(uint256[14] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 14; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_withdrawalIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _withdrawalAlpha(), _withdrawalBeta(),
            accumulator, _withdrawalGamma(),
            proof.c, _withdrawalDelta()
        );
    }

    function _decodeProof(bytes calldata encoded) private pure returns (Proof memory proof, bool valid) {
        if (encoded.length != 256) return (proof, false);
        uint256[8] memory words;
        assembly ("memory-safe") {
            let start := encoded.offset
            mstore(words, calldataload(start))
            mstore(add(words, 0x20), calldataload(add(start, 0x20)))
            mstore(add(words, 0x40), calldataload(add(start, 0x40)))
            mstore(add(words, 0x60), calldataload(add(start, 0x60)))
            mstore(add(words, 0x80), calldataload(add(start, 0x80)))
            mstore(add(words, 0xa0), calldataload(add(start, 0xa0)))
            mstore(add(words, 0xc0), calldataload(add(start, 0xc0)))
            mstore(add(words, 0xe0), calldataload(add(start, 0xe0)))
        }
        for (uint256 i = 0; i < 8; ++i) if (words[i] >= BASE_MODULUS) return (proof, false);
        proof.a = G1Point(words[0], words[1]);
        proof.b = G2Point([words[2], words[3]], [words[4], words[5]]);
        proof.c = G1Point(words[6], words[7]);
        return (proof, true);
    }

    function _negate(G1Point memory point) private pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) return G1Point(0, 0);
        return G1Point(point.x, BASE_MODULUS - (point.y % BASE_MODULUS));
    }

    function _add(G1Point memory a, G1Point memory b) private view returns (G1Point memory result, bool ok) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        assembly ("memory-safe") { ok := staticcall(gas(), 6, input, 0x80, result, 0x40) }
    }

    function _scalarMul(G1Point memory point, uint256 scalar)
        private view returns (G1Point memory result, bool ok)
    {
        uint256[3] memory input = [point.x, point.y, scalar];
        assembly ("memory-safe") { ok := staticcall(gas(), 7, input, 0x60, result, 0x40) }
    }

    function _pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) private view returns (bool) {
        uint256[24] memory input;
        _writePair(input, 0, a1, a2);
        _writePair(input, 6, b1, b2);
        _writePair(input, 12, c1, c2);
        _writePair(input, 18, d1, d2);
        uint256[1] memory output;
        bool ok;
        assembly ("memory-safe") { ok := staticcall(gas(), 8, input, 0x300, output, 0x20) }
        return ok && output[0] == 1;
    }

    function _writePair(uint256[24] memory input, uint256 offset, G1Point memory g1, G2Point memory g2)
        private pure
    {
        input[offset] = g1.x;
        input[offset + 1] = g1.y;
        // EIP-197 expects the imaginary coefficient before the real coefficient.
        input[offset + 2] = g2.x[1];
        input[offset + 3] = g2.x[0];
        input[offset + 4] = g2.y[1];
        input[offset + 5] = g2.y[0];
    }

__REQUEST_VK__

__WITHDRAWAL_VK__
}
"#
    .to_string();
    source = source.replace(
        "__REQUEST_VK__",
        &solidity_vk_functions("request", request_key),
    );
    source = source.replace(
        "__WITHDRAWAL_VK__",
        &solidity_vk_functions("withdrawal", withdrawal_key),
    );
    source
}

fn solidity_vk_functions(prefix: &str, key: &VerifyingKey<Bn254>) -> String {
    let g1 =
        |point: &G1Affine| format!("G1Point({}, {})", field_hex(&point.x), field_hex(&point.y));
    let g2 = |point: &G2Affine| {
        format!(
            "G2Point([{}, {}], [{}, {}])",
            field_hex(&point.x.c0),
            field_hex(&point.x.c1),
            field_hex(&point.y.c0),
            field_hex(&point.y.c1)
        )
    };
    let mut ic_cases = String::new();
    for (index, point) in key.gamma_abc_g1.iter().enumerate() {
        ic_cases.push_str(&format!(
            "        if (index == {index}) return {};\n",
            g1(point)
        ));
    }
    format!(
        r#"    function _{prefix}Alpha() private pure returns (G1Point memory) {{
        return {alpha};
    }}

    function _{prefix}Beta() private pure returns (G2Point memory) {{
        return {beta};
    }}

    function _{prefix}Gamma() private pure returns (G2Point memory) {{
        return {gamma};
    }}

    function _{prefix}Delta() private pure returns (G2Point memory) {{
        return {delta};
    }}

    function _{prefix}Ic(uint256 index) private pure returns (G1Point memory) {{
{ic_cases}        revert Errors.InvalidProof();
    }}"#,
        alpha = g1(&key.alpha_g1),
        beta = g2(&key.beta_g2),
        gamma = g2(&key.gamma_g2),
        delta = g2(&key.delta_g2),
    )
}

fn g1_manifest(point: &G1Affine) -> [String; 2] {
    [field_hex(&point.x), field_hex(&point.y)]
}

fn g2_manifest(point: &G2Affine) -> [[String; 2]; 2] {
    [
        [field_hex(&point.x.c0), field_hex(&point.x.c1)],
        [field_hex(&point.y.c0), field_hex(&point.y.c1)],
    ]
}

fn field_hex<F: PrimeField>(value: &F) -> String {
    format!("0x{}", hex::encode(prime_field_bytes(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_wire_preserves_coordinate_order() {
        let proof = Proof::<Bn254> {
            a: G1Affine::generator(),
            b: G2Affine::generator(),
            c: -G1Affine::generator(),
        };
        let wire = proof_to_wire(&proof).unwrap();
        assert_eq!(proof_from_wire(&wire).unwrap(), proof);
    }

    #[test]
    fn proof_wire_rejects_incomplete_or_extra_coordinates() {
        for length in [0, 255, 257, 288] {
            let wire = Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD.encode(vec![0; length]),
            };
            assert!(proof_from_wire(&wire)
                .unwrap_err()
                .to_string()
                .contains("eight 32-byte coordinates"));
        }
    }

    #[test]
    fn proof_wire_rejects_noncanonical_coordinates() {
        let mut bytes = [0; 256];
        bytes[..32].fill(0xff);
        let wire = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        assert!(proof_from_wire(&wire)
            .unwrap_err()
            .to_string()
            .contains("non-canonical BN254 base-field coordinate"));
    }

    #[test]
    fn proof_wire_rejects_invalid_curve_points() {
        let mut bytes = [0; 256];
        bytes[63] = 1;
        let wire = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        assert!(proof_from_wire(&wire)
            .unwrap_err()
            .to_string()
            .contains("invalid curve point"));
    }

    #[test]
    fn commitment_update_matches_blinding_arithmetic() {
        let blind = random_scalar();
        let rerandomization = random_scalar();
        let delta = random_scalar();
        let initial = balance_commitment(100, &blind);
        let anonymous = rerandomize(&initial, &rerandomization).unwrap();
        let updated = server_update(&anonymous, 7, &delta).unwrap();
        let expected_blind = add_blindings(&add_blindings(&blind, &rerandomization), &delta);
        assert_eq!(updated, balance_commitment(93, &expected_blind));
    }

    #[test]
    fn compact_signature_round_trip() {
        let signer = CompactSigner::from_seed(&Felt252::from_u64(42));
        let message = core::hash_felts(&[Felt252::from_u64(7)]);
        let signature = signer.sign(&message);
        assert!(signer.verify(&message, &signature).unwrap());
    }

    #[test]
    fn core_and_circuit_primitives_match() {
        let secret = Felt252::from_u64(42);
        let registration = core::registration_commitment(&secret);
        assert_eq!(
            registration,
            felt(&crate::groth16::registration_commitment(field(&secret)))
        );
        let core_leaf = core::note_leaf(7, &registration, 5_000_000, 4_000_000_000);
        let circuit_leaf =
            crate::groth16::note_leaf(7, field(&registration), 5_000_000, 4_000_000_000);
        assert_eq!(core_leaf, felt(&circuit_leaf));
        let siblings = [Felt252::ZERO; MERKLE_DEPTH];
        assert_eq!(
            core::merkle_root(7, &core_leaf, &siblings),
            felt(&crate::groth16::merkle_root(
                7,
                circuit_leaf,
                &siblings.map(|value| field(&value)),
            ))
        );
    }
}
