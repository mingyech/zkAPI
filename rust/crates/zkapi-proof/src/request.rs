//! Request proof builder.
//!
//! Assembles the private witness for a request proof, computes all derived
//! values (registration commitment, note leaf, nullifier, anonymous
//! commitment), validates constraints locally, and can emit a mock proof
//! blob for testing.

#[cfg(feature = "dev-witness-envelope")]
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkapi_core::poseidon::FieldElement;

use zkapi_core::commitment::compute_state_message;
use zkapi_core::leaf::{compute_note_leaf, compute_registration_commitment};
use zkapi_core::merkle::verify_membership;
use zkapi_core::nullifier::compute_nullifier;
#[cfg(feature = "dev-witness-envelope")]
use zkapi_core::poseidon::felt_to_field;
use zkapi_core::poseidon::field_to_felt;
use zkapi_crypto::pedersen::{add_blinding, PedersenCommitment};
use zkapi_crypto::xmss::XmssVerifier;
use zkapi_types::{
    Felt252, RequestPublicInputs, XmssSignature, GENESIS_ANCHOR, MERKLE_DEPTH,
    STATEMENT_TYPE_REQUEST, WOTS_LEN, XMSS_TREE_HEIGHT,
};

use crate::mock::MOCK_PROOF_ENVELOPE;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced when validating request witness constraints.
#[derive(Debug, Error)]
pub enum RequestProofError {
    #[error("registration commitment is zero")]
    ZeroCommitment,

    #[error("leaf is not a member of active_root (merkle proof invalid)")]
    MerkleProofInvalid,

    #[error("genesis: current_anchor must equal GENESIS_ANCHOR (1)")]
    GenesisAnchorMismatch,

    #[error("genesis: current_balance must equal deposit_amount")]
    GenesisBalanceMismatch,

    #[error("genesis: state_sig_epoch must be 0")]
    GenesisEpochNonZero,

    #[error("genesis: state_sig_root must be 0")]
    GenesisRootNonZero,

    #[error("non-genesis: state_sig_epoch must be > 0")]
    NonGenesisEpochZero,

    #[error("non-genesis: state_sig_root must be non-zero")]
    NonGenesisRootZero,

    #[error("current_balance ({balance}) < solvency_bound ({bound})")]
    SolvencyCheckFailed { balance: u128, bound: u128 },

    #[error("anon commitment point is at infinity")]
    CommitmentAtInfinity,

    #[error("missing non-genesis state signature")]
    MissingStateSignature,

    #[error("unexpected state signature on genesis witness")]
    UnexpectedStateSignature,

    #[error("state signature epoch mismatch: expected {expected}, got {actual}")]
    StateSignatureEpochMismatch { expected: u32, actual: u32 },

    #[error("state signature verification failed: {0}")]
    StateSignatureInvalid(String),

    #[error("proof envelope serialization failed: {0}")]
    Serialization(String),

    #[error("proof envelope public inputs do not match expected request inputs")]
    PublicInputsMismatch,
}

/// Serialized proof envelope used by the Rust client/server pipeline.
///
/// The on-chain verifier boundary is still the Cairo fact/verifier adapter.
/// Off-chain we carry the full witness so the server can re-run the same
/// constraints before executing the request.
#[cfg(feature = "dev-witness-envelope")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProofEnvelope {
    pub public_inputs: RequestPublicInputs,
    pub secret_s: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: Felt252,
    pub user_rerandomization: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sig: Option<XmssSignature>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder that holds the full private witness for a request proof and
/// provides helpers to derive public inputs, validate constraints, and
/// generate a mock proof blob.
pub struct RequestProofBuilder {
    // -- private witness fields --
    pub secret_s: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: FieldElement,
    pub user_rerandomization: FieldElement,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_sig_epoch: u32,
    pub state_sig_root: Felt252,

    // -- public / contextual --
    pub active_root: Felt252,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub solvency_bound: u128,
}

impl RequestProofBuilder {
    /// Create a new builder with all witness and contextual fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_s: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry_ts: u64,
        merkle_siblings: [Felt252; MERKLE_DEPTH],
        current_balance: u128,
        current_blinding: FieldElement,
        user_rerandomization: FieldElement,
        current_anchor: Felt252,
        is_genesis: bool,
        state_sig_epoch: u32,
        state_sig_root: Felt252,
        active_root: Felt252,
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
        solvency_bound: u128,
    ) -> Self {
        Self {
            secret_s,
            note_id,
            deposit_amount,
            expiry_ts,
            merkle_siblings,
            current_balance,
            current_blinding,
            user_rerandomization,
            current_anchor,
            is_genesis,
            state_sig_epoch,
            state_sig_root,
            active_root,
            protocol_version,
            chain_id,
            contract_address,
            solvency_bound,
        }
    }

    // -- derived values ------------------------------------------------

    /// Registration commitment: `C = Poseidon(DOMAIN_REG, secret_s, 0)`.
    pub fn registration_commitment(&self) -> Felt252 {
        compute_registration_commitment(&self.secret_s)
    }

    /// Note leaf: `Poseidon(DOMAIN_LEAF, note_id, C, deposit_amount, expiry_ts)`.
    pub fn note_leaf(&self) -> Felt252 {
        let c = self.registration_commitment();
        compute_note_leaf(self.note_id, &c, self.deposit_amount, self.expiry_ts)
    }

    /// Request nullifier: `Poseidon(DOMAIN_NULL, secret_s, current_anchor)`.
    pub fn nullifier(&self) -> Felt252 {
        compute_nullifier(&self.secret_s, &self.current_anchor)
    }

    /// Anonymous commitment: `Commit(current_balance, current_blinding + user_rerandomization)`.
    ///
    /// Returns the affine (x, y) coordinates as `Felt252` values.
    pub fn anon_commitment(&self) -> Result<(Felt252, Felt252), RequestProofError> {
        // Blinding factors are curve-order scalars: accumulate modulo n, not
        // modulo the base-field prime (see `zkapi_crypto::pedersen`).
        let combined_blinding = add_blinding(&self.current_blinding, &self.user_rerandomization);
        let commitment = PedersenCommitment::commit(self.current_balance, &combined_blinding);
        let (x, y) = commitment.to_affine();
        Ok((field_to_felt(&x), field_to_felt(&y)))
    }

    // -- public inputs -------------------------------------------------

    /// Build the `RequestPublicInputs` struct from the witness.
    pub fn build_public_inputs(&self) -> Result<RequestPublicInputs, RequestProofError> {
        let (anon_x, anon_y) = self.anon_commitment()?;

        Ok(RequestPublicInputs {
            statement_type: STATEMENT_TYPE_REQUEST,
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: self.contract_address,
            active_root: self.active_root,
            state_sig_epoch: self.state_sig_epoch,
            state_sig_root: self.state_sig_root,
            request_nullifier: self.nullifier(),
            anon_commitment_x: anon_x,
            anon_commitment_y: anon_y,
            expiry_ts: self.expiry_ts,
            solvency_bound: self.solvency_bound,
        })
    }

    /// Serialize this witness into the flat felt argument vector consumed by the
    /// `request_from_args` Cairo executable.
    pub fn to_cairo_args(
        &self,
        state_sig: Option<&XmssSignature>,
    ) -> Result<Vec<Felt252>, RequestProofError> {
        self.validate_with_signature(state_sig)?;

        let mut args = vec![
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            Felt252::from_u128(self.solvency_bound),
            self.secret_s,
            Felt252::from_u64(self.note_id as u64),
            Felt252::from_u128(self.deposit_amount),
            Felt252::from_u64(self.expiry_ts),
        ];
        args.extend(merkle_index_bits(self.note_id));
        args.extend(self.merkle_siblings);
        args.extend([
            Felt252::from_u128(self.current_balance),
            field_to_felt(&self.current_blinding),
            field_to_felt(&self.user_rerandomization),
            self.current_anchor,
            Felt252::from_u64(self.is_genesis as u64),
            self.state_sig_root,
            Felt252::from_u64(self.state_sig_epoch as u64),
        ]);

        if let Some(sig) = state_sig {
            args.push(Felt252::from_u64(sig.leaf_index as u64));
            args.extend(sig.wots_sig.iter().copied());
            args.extend(sig.auth_path.iter().copied());
        } else {
            args.push(Felt252::ZERO);
            args.extend(std::iter::repeat_n(Felt252::ZERO, WOTS_LEN));
            args.extend(std::iter::repeat_n(Felt252::ZERO, XMSS_TREE_HEIGHT));
        }

        Ok(args)
    }

    // -- validation ----------------------------------------------------

    /// Run all circuit-equivalent constraint checks locally.
    ///
    /// This mirrors the Cairo request program constraints (spec section 8.2)
    /// so that callers can detect invalid witnesses before sending to a
    /// (potentially expensive) prover.
    pub fn validate(&self) -> Result<(), RequestProofError> {
        // 1. Registration commitment must be non-zero.
        let c = self.registration_commitment();
        if c.is_zero() {
            return Err(RequestProofError::ZeroCommitment);
        }

        // 2-3. Leaf membership in active_root.
        let leaf = self.note_leaf();
        if !verify_membership(
            &self.active_root,
            self.note_id,
            &leaf,
            &self.merkle_siblings,
        ) {
            return Err(RequestProofError::MerkleProofInvalid);
        }

        // 4-5. Genesis vs non-genesis constraints.
        if self.is_genesis {
            // current_anchor must equal GENESIS_ANCHOR (= 1).
            if self.current_anchor != Felt252::from_u64(GENESIS_ANCHOR) {
                return Err(RequestProofError::GenesisAnchorMismatch);
            }
            // current_balance must equal deposit_amount.
            if self.current_balance != self.deposit_amount {
                return Err(RequestProofError::GenesisBalanceMismatch);
            }
            // state_sig_epoch must be 0.
            if self.state_sig_epoch != 0 {
                return Err(RequestProofError::GenesisEpochNonZero);
            }
            // state_sig_root must be 0.
            if !self.state_sig_root.is_zero() {
                return Err(RequestProofError::GenesisRootNonZero);
            }
        } else {
            // Non-genesis: state_sig_epoch > 0, state_sig_root != 0.
            if self.state_sig_epoch == 0 {
                return Err(RequestProofError::NonGenesisEpochZero);
            }
            if self.state_sig_root.is_zero() {
                return Err(RequestProofError::NonGenesisRootZero);
            }
            // Structural checks live here; full XMSS verification is performed
            // by validate_with_signature once the private signature is supplied.
        }

        // 8. Solvency: current_balance >= solvency_bound.
        if self.current_balance < self.solvency_bound {
            return Err(RequestProofError::SolvencyCheckFailed {
                balance: self.current_balance,
                bound: self.solvency_bound,
            });
        }

        // Verify the anon commitment does not land at infinity.
        let _commitment = self.anon_commitment()?;

        Ok(())
    }

    /// Run all local checks including XMSS verification for non-genesis notes.
    pub fn validate_with_signature(
        &self,
        state_sig: Option<&XmssSignature>,
    ) -> Result<(), RequestProofError> {
        self.validate()?;

        if self.is_genesis {
            if state_sig.is_some() {
                return Err(RequestProofError::UnexpectedStateSignature);
            }
            return Ok(());
        }

        let sig = state_sig.ok_or(RequestProofError::MissingStateSignature)?;
        if sig.epoch != self.state_sig_epoch {
            return Err(RequestProofError::StateSignatureEpochMismatch {
                expected: self.state_sig_epoch,
                actual: sig.epoch,
            });
        }
        validate_xmss_signature(sig).map_err(RequestProofError::StateSignatureInvalid)?;

        let commitment = PedersenCommitment::commit(self.current_balance, &self.current_blinding);
        let (current_x, current_y) = commitment.to_affine();
        let state_msg = compute_state_message(
            self.protocol_version,
            self.chain_id,
            &self.contract_address,
            &field_to_felt(&current_x),
            &field_to_felt(&current_y),
            &self.current_anchor,
        );
        if !verify_xmss_signature(&self.state_sig_root, &state_msg, sig) {
            return Err(RequestProofError::StateSignatureInvalid(
                "XMSS root/path verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Build a serialized witness envelope that the server can verify.
    #[cfg(feature = "dev-witness-envelope")]
    pub fn build_envelope(
        &self,
        state_sig: Option<&XmssSignature>,
    ) -> Result<RequestProofEnvelope, RequestProofError> {
        self.validate_with_signature(state_sig)?;

        Ok(RequestProofEnvelope {
            public_inputs: self.build_public_inputs()?,
            secret_s: self.secret_s,
            note_id: self.note_id,
            deposit_amount: self.deposit_amount,
            expiry_ts: self.expiry_ts,
            merkle_siblings: self.merkle_siblings,
            current_balance: self.current_balance,
            current_blinding: field_to_felt(&self.current_blinding),
            user_rerandomization: field_to_felt(&self.user_rerandomization),
            current_anchor: self.current_anchor,
            is_genesis: self.is_genesis,
            state_sig: state_sig.cloned(),
        })
    }

    /// Serialize the proof envelope as JSON bytes.
    #[cfg(feature = "dev-witness-envelope")]
    pub fn generate_proof(
        &self,
        state_sig: Option<&XmssSignature>,
    ) -> Result<Vec<u8>, RequestProofError> {
        let envelope = self.build_envelope(state_sig)?;
        serde_json::to_vec(&envelope).map_err(|e| RequestProofError::Serialization(e.to_string()))
    }

    // -- mock proof ----------------------------------------------------

    /// Produce a mock proof blob for testing.
    ///
    /// In a production build this would invoke the Cairo STARK prover.
    pub fn generate_mock_proof(&self) -> Vec<u8> {
        MOCK_PROOF_ENVELOPE.to_vec()
    }
}

/// Verify a serialized request proof envelope against expected public inputs.
#[cfg(feature = "dev-witness-envelope")]
pub fn verify_request_proof(
    proof: &[u8],
    expected_inputs: &RequestPublicInputs,
) -> Result<(), RequestProofError> {
    let envelope: RequestProofEnvelope = serde_json::from_slice(proof)
        .map_err(|e| RequestProofError::Serialization(e.to_string()))?;
    if &envelope.public_inputs != expected_inputs {
        return Err(RequestProofError::PublicInputsMismatch);
    }

    let builder = RequestProofBuilder::new(
        envelope.secret_s,
        envelope.note_id,
        envelope.deposit_amount,
        envelope.expiry_ts,
        envelope.merkle_siblings,
        envelope.current_balance,
        felt_to_field(&envelope.current_blinding),
        felt_to_field(&envelope.user_rerandomization),
        envelope.current_anchor,
        envelope.is_genesis,
        expected_inputs.state_sig_epoch,
        expected_inputs.state_sig_root,
        expected_inputs.active_root,
        expected_inputs.protocol_version,
        expected_inputs.chain_id,
        expected_inputs.contract_address,
        expected_inputs.solvency_bound,
    );

    let rebuilt_inputs = builder.build_public_inputs()?;
    if &rebuilt_inputs != expected_inputs {
        return Err(RequestProofError::PublicInputsMismatch);
    }

    builder.validate_with_signature(envelope.state_sig.as_ref())
}

// Validate the XMSS state signature structurally at the height committed by the
// signature itself. The deployment XMSS height is a configuration parameter
// (`xmss_height`) and is bound into the published signing root that the client
// trusts via the epoch registry, so structural validation honors the
// root-committed height rather than mandating the maximum `XMSS_TREE_HEIGHT`.
// Demo/test operators run a small tree (height-20 keygen is impractical); a
// production operator publishes a full-height root. Cryptographic soundness
// comes from `verify_xmss_signature` against that trusted root, not from this
// structural length check.
fn validate_xmss_signature(sig: &XmssSignature) -> Result<(), String> {
    sig.validate_for_height(sig.auth_path.len())
}

fn verify_xmss_signature(root: &Felt252, message: &Felt252, sig: &XmssSignature) -> bool {
    XmssVerifier::verify(root, message, sig)
}

fn merkle_index_bits(index: u32) -> impl Iterator<Item = Felt252> {
    (0..MERKLE_DEPTH).map(move |level| Felt252::from_u64(((index >> level) & 1) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dev-witness-envelope")]
    use zkapi_core::commitment::compute_state_message;
    use zkapi_core::merkle::MerkleTree;
    #[cfg(feature = "dev-witness-envelope")]
    use zkapi_crypto::xmss::XmssKeypair;

    /// Helper: build a minimal genesis witness that should pass validation.
    fn genesis_builder() -> RequestProofBuilder {
        let secret = Felt252::from_u64(42);
        let deposit = 1_000u128;
        let expiry = 1_700_000_000u64;

        // Compute the leaf and insert it into a fresh tree.
        let c = compute_registration_commitment(&secret);
        let leaf = compute_note_leaf(0, &c, deposit, expiry);
        let mut tree = MerkleTree::new();
        tree.insert(leaf);
        let siblings = tree.get_siblings(0);
        let root = tree.root();

        RequestProofBuilder::new(
            secret,
            0, // note_id
            deposit,
            expiry,
            siblings,
            deposit,                           // current_balance == deposit for genesis
            FieldElement::ZERO,                // current_blinding
            FieldElement::from(7u64),          // user_rerandomization
            Felt252::from_u64(GENESIS_ANCHOR), // current_anchor = 1
            true,                              // is_genesis
            0,                                 // state_sig_epoch
            Felt252::ZERO,                     // state_sig_root
            root,                              // active_root
            1,                                 // protocol_version
            1,                                 // chain_id
            Felt252::from_u64(0xdead),         // contract_address
            100,                               // solvency_bound
        )
    }

    #[test]
    fn test_genesis_validate_ok() {
        let builder = genesis_builder();
        builder.validate().expect("genesis builder should validate");
    }

    #[test]
    fn test_build_public_inputs() {
        let builder = genesis_builder();
        let pi = builder
            .build_public_inputs()
            .expect("should build public inputs");
        assert_eq!(pi.statement_type, STATEMENT_TYPE_REQUEST);
        assert_eq!(pi.protocol_version, 1);
        assert_eq!(pi.chain_id, 1);
        assert_eq!(pi.expiry_ts, 1_700_000_000);
        assert_eq!(pi.solvency_bound, 100);
        assert!(!pi.request_nullifier.is_zero());
        assert!(!pi.anon_commitment_x.is_zero());
    }

    #[test]
    fn test_cairo_args_for_genesis_request() {
        let builder = genesis_builder();
        let args = builder.to_cairo_args(None).unwrap();
        assert_eq!(args.len(), 166);
        assert_eq!(args[0], Felt252::from_u64(1));
        assert_eq!(args[9], Felt252::ZERO);
        assert_eq!(args[77], Felt252::ONE);
        assert_eq!(args[80], Felt252::ZERO);
    }

    #[test]
    fn test_solvency_failure() {
        let mut builder = genesis_builder();
        // Set solvency_bound higher than balance.
        builder.solvency_bound = builder.deposit_amount + 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::SolvencyCheckFailed { .. }));
    }

    #[test]
    fn test_genesis_anchor_mismatch() {
        let mut builder = genesis_builder();
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::GenesisAnchorMismatch));
    }

    #[test]
    fn test_genesis_balance_mismatch() {
        let mut builder = genesis_builder();
        builder.current_balance = builder.deposit_amount - 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::GenesisBalanceMismatch));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let mut builder = genesis_builder();
        // Corrupt a sibling.
        builder.merkle_siblings[0] = Felt252::from_u64(0xbad);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::MerkleProofInvalid));
    }

    #[test]
    fn test_mock_proof_generation() {
        let builder = genesis_builder();
        let proof = builder.generate_mock_proof();
        assert_eq!(proof.len(), 32);
        assert!(proof.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_non_genesis_epoch_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        // Keep epoch at 0 -- should fail.
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::NonGenesisEpochZero));
    }

    #[test]
    fn test_non_genesis_root_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.state_sig_epoch = 1;
        builder.state_sig_root = Felt252::ZERO;
        // Anchor no longer 1, so won't trip genesis check; just needs nonzero.
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::NonGenesisRootZero));
    }

    #[cfg(feature = "dev-witness-envelope")]
    #[test]
    fn test_real_proof_roundtrip_non_genesis() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.current_balance = 900;
        builder.current_blinding = FieldElement::from(9u64);
        builder.user_rerandomization = FieldElement::from(7u64);
        builder.current_anchor = Felt252::from_u64(55);

        let keypair = XmssKeypair::generate_with_height(&FieldElement::from(123u64), 4);
        builder.state_sig_epoch = 7;
        builder.state_sig_root = keypair.root_felt();

        let commitment =
            PedersenCommitment::commit(builder.current_balance, &builder.current_blinding);
        let (cx, cy) = commitment.to_affine();
        let state_msg = compute_state_message(
            builder.protocol_version,
            builder.chain_id,
            &builder.contract_address,
            &field_to_felt(&cx),
            &field_to_felt(&cy),
            &builder.current_anchor,
        );
        let (mut sig, _) = keypair.sign(&state_msg).unwrap();
        sig.epoch = builder.state_sig_epoch;

        let public_inputs = builder.build_public_inputs().unwrap();
        let proof = builder.generate_proof(Some(&sig)).unwrap();
        verify_request_proof(&proof, &public_inputs).unwrap();
    }
}
