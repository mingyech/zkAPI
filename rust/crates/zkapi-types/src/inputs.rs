//! Public input structs for request and withdrawal proofs.
//!
//! These structs must match the Cairo public outputs field-for-field,
//! and the Solidity Types.sol definitions exactly.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{Felt252, STATEMENT_TYPE_REQUEST, STATEMENT_TYPE_WITHDRAWAL};

/// Public statement verified for every v2 API request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestPublicInputsV2 {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: Felt252,
    pub authorization_tag: Felt252,
    pub anonymous_commitment_x: Felt252,
    pub anonymous_commitment_y: Felt252,
}

impl RequestPublicInputsV2 {
    pub fn to_field_elements(&self) -> [Felt252; 12] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key_x,
            self.state_signing_key_y,
            Felt252::from_u64(self.request_time),
            Felt252::from_u128(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment_x,
            self.anonymous_commitment_y,
        ]
    }
}

/// Public statement verified for a v2 mutual or escape withdrawal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalPublicInputsV2 {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub clearance_signing_key_x: Felt252,
    pub clearance_signing_key_y: Felt252,
    pub note_id: u32,
    pub final_balance: u128,
    pub destination: [u8; 20],
    pub withdrawal_nullifier: Felt252,
    pub has_clearance: bool,
    pub withdrawal_tag: Felt252,
}

impl WithdrawalPublicInputsV2 {
    pub fn destination_field(&self) -> Felt252 {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&self.destination);
        Felt252(bytes)
    }

    pub fn to_field_elements(&self) -> [Felt252; 14] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key_x,
            self.state_signing_key_y,
            self.clearance_signing_key_x,
            self.clearance_signing_key_y,
            Felt252::from_u64(self.note_id as u64),
            Felt252::from_u128(self.final_balance),
            self.destination_field(),
            self.withdrawal_nullifier,
            Felt252::from_u64(self.has_clearance as u64),
            self.withdrawal_tag,
        ]
    }
}

/// Hash the exact client request id and payload digest into the private context
/// that the request proof binds through `authorization_tag`.
pub fn canonical_request_context(client_request_id: &str, payload_hash: &Felt252) -> Felt252 {
    let id = client_request_id.as_bytes();
    let mut bytes = Vec::with_capacity(8 + id.len() + 32);
    bytes.extend_from_slice(&(id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(payload_hash.as_bytes());
    hash_bytes_to_felt(b"zkapi.v2.request-context", &bytes)
}

/// Public inputs for a request proof.
///
/// The Cairo request program emits these as public outputs in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestPublicInputs {
    /// Must be 1 for request proofs.
    pub statement_type: u8,
    pub protocol_version: u16,
    pub chain_id: u64,
    /// Ethereum address as felt (< 2^160).
    pub contract_address: Felt252,
    pub active_root: Felt252,
    /// 0 for genesis path.
    pub state_sig_epoch: u32,
    /// 0 for genesis path.
    pub state_sig_root: Felt252,
    pub request_nullifier: Felt252,
    pub anon_commitment_x: Felt252,
    pub anon_commitment_y: Felt252,
    pub expiry_ts: u64,
    pub solvency_bound: u128,
}

impl RequestPublicInputs {
    pub fn to_cairo_outputs(&self) -> Vec<Felt252> {
        vec![
            Felt252::from_u64(self.statement_type as u64),
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            Felt252::from_u64(self.state_sig_epoch as u64),
            self.state_sig_root,
            self.request_nullifier,
            self.anon_commitment_x,
            self.anon_commitment_y,
            Felt252::from_u64(self.expiry_ts),
            Felt252::from_u128(self.solvency_bound),
        ]
    }

    pub fn public_output_hash(&self) -> Felt252 {
        hash_felts_to_felt(b"zkapi.req.outputs.v1", &self.to_cairo_outputs())
    }
}

pub fn request_public_output_hash_from_outputs(outputs: &[Felt252]) -> Result<Felt252, String> {
    if outputs.len() != 12 {
        return Err(format!(
            "request proof emitted {} public outputs, expected 12",
            outputs.len()
        ));
    }
    if outputs[0].to_u64() != Some(STATEMENT_TYPE_REQUEST as u64) {
        return Err("request proof emitted wrong statement_type".to_string());
    }
    Ok(hash_felts_to_felt(b"zkapi.req.outputs.v1", outputs))
}

/// Public inputs for a withdrawal proof.
///
/// The Cairo withdrawal program emits these as public outputs in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalPublicInputs {
    /// Must be 2 for withdrawal proofs.
    pub statement_type: u8,
    pub protocol_version: u16,
    pub chain_id: u64,
    /// Ethereum address as felt (< 2^160).
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub note_id: u32,
    pub final_balance: u128,
    /// Ethereum address (20 bytes).
    pub destination: [u8; 20],
    pub withdrawal_nullifier: Felt252,
    pub is_genesis: bool,
    pub has_clearance: bool,
    /// 0 for genesis path.
    pub state_sig_epoch: u32,
    /// 0 for genesis path.
    pub state_sig_root: Felt252,
    /// 0 when has_clearance is false.
    pub clear_sig_epoch: u32,
    /// 0 when has_clearance is false.
    pub clear_sig_root: Felt252,
}

impl WithdrawalPublicInputs {
    pub fn to_cairo_outputs(&self) -> Vec<Felt252> {
        let mut destination = [0u8; 32];
        destination[12..].copy_from_slice(&self.destination);
        vec![
            Felt252::from_u64(self.statement_type as u64),
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            Felt252::from_u64(self.note_id as u64),
            Felt252::from_u128(self.final_balance),
            Felt252(destination),
            self.withdrawal_nullifier,
            Felt252::from_u64(self.is_genesis as u64),
            Felt252::from_u64(self.has_clearance as u64),
            Felt252::from_u64(self.state_sig_epoch as u64),
            self.state_sig_root,
            Felt252::from_u64(self.clear_sig_epoch as u64),
            self.clear_sig_root,
        ]
    }

    pub fn public_output_hash(&self) -> Felt252 {
        hash_felts_to_felt(b"zkapi.wd.outputs.v1", &self.to_cairo_outputs())
    }
}

pub fn withdrawal_public_output_hash_from_outputs(outputs: &[Felt252]) -> Result<Felt252, String> {
    if outputs.len() != 15 {
        return Err(format!(
            "withdrawal proof emitted {} public outputs, expected 15",
            outputs.len()
        ));
    }
    if outputs[0].to_u64() != Some(STATEMENT_TYPE_WITHDRAWAL as u64) {
        return Err("withdrawal proof emitted wrong statement_type".to_string());
    }
    Ok(hash_felts_to_felt(b"zkapi.wd.outputs.v1", outputs))
}

pub fn public_output_hash_from_cairo_outputs(outputs: &[Felt252]) -> Result<Felt252, String> {
    match outputs.first().and_then(Felt252::to_u64) {
        Some(statement_type) if statement_type == STATEMENT_TYPE_REQUEST as u64 => {
            request_public_output_hash_from_outputs(outputs)
        }
        Some(statement_type) if statement_type == STATEMENT_TYPE_WITHDRAWAL as u64 => {
            withdrawal_public_output_hash_from_outputs(outputs)
        }
        Some(statement_type) => Err(format!("unknown statement_type {statement_type}")),
        None => Err("proof emitted no public outputs".to_string()),
    }
}

pub fn canonical_payload_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.payload.v1", payload)
}

pub fn canonical_response_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.response.v1", payload)
}

fn hash_felts_to_felt(domain: &[u8], felts: &[Felt252]) -> Felt252 {
    let mut bytes = Vec::with_capacity(felts.len() * 32);
    for felt in felts {
        bytes.extend_from_slice(felt.as_bytes());
    }
    hash_bytes_to_felt(domain, &bytes)
}

fn hash_bytes_to_felt(domain: &[u8], payload: &[u8]) -> Felt252 {
    let mut counter = 0u32;
    loop {
        let mut h = Keccak256::new();
        h.update(domain);
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
        h.update(counter.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if let Ok(felt) = Felt252::try_from_bytes_be(digest) {
            return felt;
        }
        counter = counter
            .checked_add(1)
            .expect("hash-to-felt counter exhausted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_outputs_are_canonical_felt_slots() {
        let inputs = RequestPublicInputs {
            statement_type: 1,
            protocol_version: 2,
            chain_id: 3,
            contract_address: Felt252::from_u64(4),
            active_root: Felt252::from_u64(5),
            state_sig_epoch: 6,
            state_sig_root: Felt252::from_u64(7),
            request_nullifier: Felt252::from_u64(8),
            anon_commitment_x: Felt252::from_u64(9),
            anon_commitment_y: Felt252::from_u64(10),
            expiry_ts: 11,
            solvency_bound: 12,
        };
        let outputs = inputs.to_cairo_outputs();
        assert_eq!(outputs.len(), 12);
        assert_eq!(outputs[0], Felt252::from_u64(1));
        assert_eq!(outputs[5], Felt252::from_u64(6));
        assert_eq!(outputs[11], Felt252::from_u128(12));
        assert_eq!(inputs.public_output_hash(), inputs.public_output_hash());
    }

    #[test]
    fn withdrawal_outputs_encode_bool_and_address_as_felts() {
        let mut destination = [0u8; 20];
        destination[19] = 0xaa;
        let inputs = WithdrawalPublicInputs {
            statement_type: 2,
            protocol_version: 1,
            chain_id: 3,
            contract_address: Felt252::from_u64(4),
            active_root: Felt252::from_u64(5),
            note_id: 6,
            final_balance: 7,
            destination,
            withdrawal_nullifier: Felt252::from_u64(8),
            is_genesis: true,
            has_clearance: false,
            state_sig_epoch: 9,
            state_sig_root: Felt252::from_u64(10),
            clear_sig_epoch: 11,
            clear_sig_root: Felt252::from_u64(12),
        };
        let outputs = inputs.to_cairo_outputs();
        assert_eq!(outputs.len(), 15);
        assert_eq!(outputs[7].as_bytes()[31], 0xaa);
        assert_eq!(outputs[9], Felt252::ONE);
        assert_eq!(outputs[10], Felt252::ZERO);
        assert_eq!(inputs.public_output_hash(), inputs.public_output_hash());
    }

    #[test]
    fn payload_and_response_hashes_are_domain_separated() {
        let payload = b"{\"ok\":true}";
        assert_eq!(
            canonical_payload_hash(payload),
            canonical_payload_hash(payload)
        );
        assert_eq!(
            canonical_response_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_payload_hash(b"other")
        );
    }

    #[cfg(any())]
    #[test]
    fn fact_vectors_for_solidity_sync_are_stable() {
        let request = RequestPublicInputs {
            statement_type: 1,
            protocol_version: 1,
            chain_id: 31337,
            contract_address: Felt252::from_u64(0x1234),
            active_root: Felt252::from_u64(5),
            state_sig_epoch: 6,
            state_sig_root: Felt252::from_u64(7),
            request_nullifier: Felt252::from_u64(8),
            anon_commitment_x: Felt252::from_u64(9),
            anon_commitment_y: Felt252::from_u64(10),
            expiry_ts: 11,
            solvency_bound: 12,
        };
        let mut destination = [0u8; 20];
        destination[18] = 0xbe;
        destination[19] = 0xef;
        let withdrawal = WithdrawalPublicInputs {
            statement_type: 2,
            protocol_version: 1,
            chain_id: 31337,
            contract_address: Felt252::from_u64(0x1234),
            active_root: Felt252::from_u64(5),
            note_id: 6,
            final_balance: 7,
            destination,
            withdrawal_nullifier: Felt252::from_u64(8),
            is_genesis: true,
            has_clearance: false,
            state_sig_epoch: 0,
            state_sig_root: Felt252::ZERO,
            clear_sig_epoch: 0,
            clear_sig_root: Felt252::ZERO,
        };
        assert_eq!(
            request.public_output_hash().to_hex(),
            "0x3964139c5f6f84608232748c75a34ce4c7d828c52b0d044ac404ae7e66644c6"
        );
        assert_eq!(
            withdrawal.public_output_hash().to_hex(),
            "0x4c7faba541192c69c4c3817847f7829c4581910a5bb8fa8381969893ec6ecf3"
        );
    }
}
