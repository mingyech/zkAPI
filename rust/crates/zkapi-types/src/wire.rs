//! Wire format types for HTTP APIs.
//!
//! JSON serialization rules per spec section 12.1:
//! - field elements: 0x-prefixed lowercase hex strings
//! - curve points: objects with x and y hex fields
//! - u128/u64/u32: decimal strings in JSON
//! - proof blobs: base64 strings
//! - UUIDs: canonical textual form

use serde::{Deserialize, Serialize};

use crate::Felt252;

/// Supported opaque proof artifact backends on the wire.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendWire {
    StwoCairo,
    Groth16Bn254,
}

/// Opaque proof artifact sent across runtime boundaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofArtifactWire {
    pub backend: ProofBackendWire,
    pub public_output_hash: Felt252,
    /// Base64-encoded opaque proof bytes.
    pub proof: String,
}

/// Compact Groth16 proof artifact. Public inputs are carried in the enclosing
/// request and are verified directly; there is no separately trusted output
/// hash or witness envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16ProofWire {
    pub backend: ProofBackendWire,
    /// Arkworks canonical compressed proof bytes, base64 encoded.
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequestV2 {
    pub client_request_id: String,
    pub payload: String,
    pub payload_hash: Felt252,
    pub public_inputs: crate::RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseV2 {
    pub status: String,
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_payload: String,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_signature: crate::SchnorrSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceResponseV2 {
    pub status: String,
    pub withdrawal_nullifier: Felt252,
    pub signature: crate::SchnorrSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponseV2 {
    pub status: String,
    pub nullifier_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_response: Option<RequestResponseV2>,
}

/// A curve point serialized as {x, y} hex fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurvePointWire {
    pub x: Felt252,
    pub y: Felt252,
}

/// Successful request response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponse {
    pub status: String,
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_payload: String,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_sig_epoch: u32,
    pub next_state_sig_root: Felt252,
    pub next_state_sig: crate::XmssSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub client_request_id: String,
    pub error_code: String,
    pub error_message: String,
    pub retriable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_root: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_ms: Option<u64>,
}

/// API request payload sent by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub client_request_id: String,
    pub payload: String,
    pub payload_hash: Felt252,
    pub public_inputs: crate::RequestPublicInputs,
    pub proof: ProofArtifactWire,
}

/// Clearance request for mutual close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceRequest {
    pub withdrawal_nullifier: Felt252,
}

/// Clearance response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceResponse {
    pub status: String,
    pub withdrawal_nullifier: Felt252,
    pub clear_sig_epoch: u32,
    pub clear_sig_root: Felt252,
    pub clear_sig: crate::XmssSignature,
}

/// Recovery response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponse {
    pub status: String,
    pub nullifier_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_response: Option<RequestResponse>,
}
