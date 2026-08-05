//! Withdrawal proof builder.
//!
//! Assembles the private witness for a withdrawal proof, computes all
//! derived values (registration commitment, note leaf, nullifier),
//! validates constraints locally, and can emit a mock proof blob for
//! testing.

#[cfg(feature = "dev-witness-envelope")]
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkapi_core::poseidon::FieldElement;

use zkapi_core::commitment::{compute_clearance_message, compute_state_message};
use zkapi_core::leaf::{compute_note_leaf, compute_registration_commitment};
use zkapi_core::merkle::verify_membership;
use zkapi_core::nullifier::compute_nullifier;
#[cfg(feature = "dev-witness-envelope")]
use zkapi_core::poseidon::felt_to_field;
use zkapi_core::poseidon::field_to_felt;
use zkapi_crypto::pedersen::PedersenCommitment;
use zkapi_crypto::xmss::XmssVerifier;
use zkapi_types::serialization::address_to_felt;
use zkapi_types::{
    Felt252, WithdrawalPublicInputs, XmssSignature, GENESIS_ANCHOR, MERKLE_DEPTH,
    STATEMENT_TYPE_WITHDRAWAL, WOTS_LEN, XMSS_TREE_HEIGHT,
};

use crate::mock::MOCK_PROOF_ENVELOPE;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced when validating withdrawal witness constraints.
#[derive(Debug, Error)]
pub enum WithdrawalProofError {
    #[error("registration commitment is zero")]
    ZeroCommitment,

    #[error("leaf is not a member of active_root (merkle proof invalid)")]
    MerkleProofInvalid,

    #[error("genesis: current_anchor must equal GENESIS_ANCHOR (1)")]
    GenesisAnchorMismatch,

    #[error("genesis: final_balance must equal deposit_amount")]
    GenesisBalanceMismatch,

    #[error("genesis: state_sig_epoch must be 0")]
    GenesisEpochNonZero,

    #[error("genesis: state_sig_root must be 0")]
    GenesisRootNonZero,

    #[error("non-genesis: state_sig_epoch must be > 0")]
    NonGenesisEpochZero,

    #[error("non-genesis: state_sig_root must be non-zero")]
    NonGenesisRootZero,

    #[error("final_balance ({final_balance}) > deposit_amount ({deposit_amount})")]
    BalanceExceedsDeposit {
        final_balance: u128,
        deposit_amount: u128,
    },

    #[error("clearance: clear_sig_epoch must be > 0")]
    ClearanceEpochZero,

    #[error("clearance: clear_sig_root must be non-zero")]
    ClearanceRootZero,

    #[error("no-clearance: clear_sig_epoch must be 0")]
    NoClearanceEpochNonZero,

    #[error("no-clearance: clear_sig_root must be 0")]
    NoClearanceRootNonZero,

    #[error("missing non-genesis state signature")]
    MissingStateSignature,

    #[error("unexpected state signature on genesis witness")]
    UnexpectedStateSignature,

    #[error("state signature epoch mismatch: expected {expected}, got {actual}")]
    StateSignatureEpochMismatch { expected: u32, actual: u32 },

    #[error("state signature verification failed: {0}")]
    StateSignatureInvalid(String),

    #[error("missing clearance signature")]
    MissingClearanceSignature,

    #[error("unexpected clearance signature without clearance flag")]
    UnexpectedClearanceSignature,

    #[error("clearance signature epoch mismatch: expected {expected}, got {actual}")]
    ClearanceSignatureEpochMismatch { expected: u32, actual: u32 },

    #[error("clearance signature verification failed: {0}")]
    ClearanceSignatureInvalid(String),

    #[error("proof envelope serialization failed: {0}")]
    Serialization(String),

    #[error("proof envelope public inputs do not match expected withdrawal inputs")]
    PublicInputsMismatch,
}

/// Serialized withdrawal proof envelope used by the Rust client/server pipeline.
#[cfg(feature = "dev-witness-envelope")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofEnvelope {
    pub public_inputs: WithdrawalPublicInputs,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub final_blinding: Felt252,
    pub current_anchor: Felt252,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sig: Option<XmssSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_sig: Option<XmssSignature>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder that holds the full private witness for a withdrawal proof and
/// provides helpers to derive public inputs, validate constraints, and
/// generate a mock proof blob.
pub struct WithdrawalProofBuilder {
    // -- private witness fields --
    pub secret_s: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub final_balance: u128,
    pub final_blinding: FieldElement,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_sig_epoch: u32,
    pub state_sig_root: Felt252,
    pub has_clearance: bool,
    pub clear_sig_epoch: u32,
    pub clear_sig_root: Felt252,
    pub destination: [u8; 20],

    // -- public / contextual --
    pub active_root: Felt252,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
}

impl WithdrawalProofBuilder {
    /// Create a new builder with all witness and contextual fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_s: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry_ts: u64,
        merkle_siblings: [Felt252; MERKLE_DEPTH],
        final_balance: u128,
        final_blinding: FieldElement,
        current_anchor: Felt252,
        is_genesis: bool,
        state_sig_epoch: u32,
        state_sig_root: Felt252,
        has_clearance: bool,
        clear_sig_epoch: u32,
        clear_sig_root: Felt252,
        destination: [u8; 20],
        active_root: Felt252,
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
    ) -> Self {
        Self {
            secret_s,
            note_id,
            deposit_amount,
            expiry_ts,
            merkle_siblings,
            final_balance,
            final_blinding,
            current_anchor,
            is_genesis,
            state_sig_epoch,
            state_sig_root,
            has_clearance,
            clear_sig_epoch,
            clear_sig_root,
            destination,
            active_root,
            protocol_version,
            chain_id,
            contract_address,
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

    /// Withdrawal nullifier: `Poseidon(DOMAIN_NULL, secret_s, current_anchor)`.
    pub fn nullifier(&self) -> Felt252 {
        compute_nullifier(&self.secret_s, &self.current_anchor)
    }

    // -- public inputs -------------------------------------------------

    /// Build the `WithdrawalPublicInputs` struct from the witness.
    pub fn build_public_inputs(&self) -> WithdrawalPublicInputs {
        WithdrawalPublicInputs {
            statement_type: STATEMENT_TYPE_WITHDRAWAL,
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: self.contract_address,
            active_root: self.active_root,
            note_id: self.note_id,
            final_balance: self.final_balance,
            destination: self.destination,
            withdrawal_nullifier: self.nullifier(),
            is_genesis: self.is_genesis,
            has_clearance: self.has_clearance,
            state_sig_epoch: self.state_sig_epoch,
            state_sig_root: self.state_sig_root,
            clear_sig_epoch: self.clear_sig_epoch,
            clear_sig_root: self.clear_sig_root,
        }
    }

    /// Serialize this witness into the flat felt argument vector consumed by the
    /// `withdrawal_from_args` Cairo executable.
    pub fn to_cairo_args(
        &self,
        state_sig: Option<&XmssSignature>,
        clear_sig: Option<&XmssSignature>,
    ) -> Result<Vec<Felt252>, WithdrawalProofError> {
        self.validate_with_signatures(state_sig, clear_sig)?;

        let mut args = vec![
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            address_to_felt(&self.destination),
            self.secret_s,
            Felt252::from_u64(self.note_id as u64),
            Felt252::from_u128(self.deposit_amount),
            Felt252::from_u64(self.expiry_ts),
        ];
        args.extend(merkle_index_bits(self.note_id));
        args.extend(self.merkle_siblings);
        args.extend([
            Felt252::from_u128(self.final_balance),
            field_to_felt(&self.final_blinding),
            self.current_anchor,
            Felt252::from_u64(self.is_genesis as u64),
            self.state_sig_root,
            Felt252::from_u64(self.state_sig_epoch as u64),
        ]);

        append_signature_args(&mut args, state_sig);
        args.extend([
            Felt252::from_u64(self.has_clearance as u64),
            self.clear_sig_root,
            Felt252::from_u64(self.clear_sig_epoch as u64),
        ]);
        append_signature_args(&mut args, clear_sig);

        Ok(args)
    }

    // -- validation ----------------------------------------------------

    /// Run all circuit-equivalent constraint checks locally.
    ///
    /// This mirrors the Cairo withdrawal program constraints (spec section 8.3)
    /// so that callers can detect invalid witnesses before sending to a
    /// (potentially expensive) prover.
    pub fn validate(&self) -> Result<(), WithdrawalProofError> {
        // 1. Registration commitment must be non-zero.
        let c = self.registration_commitment();
        if c.is_zero() {
            return Err(WithdrawalProofError::ZeroCommitment);
        }

        // 2-3. Leaf membership in active_root.
        let leaf = self.note_leaf();
        if !verify_membership(
            &self.active_root,
            self.note_id,
            &leaf,
            &self.merkle_siblings,
        ) {
            return Err(WithdrawalProofError::MerkleProofInvalid);
        }

        // 4-5. Genesis vs non-genesis state validity.
        if self.is_genesis {
            // current_anchor must equal GENESIS_ANCHOR (= 1).
            if self.current_anchor != Felt252::from_u64(GENESIS_ANCHOR) {
                return Err(WithdrawalProofError::GenesisAnchorMismatch);
            }
            // final_balance must equal deposit_amount.
            if self.final_balance != self.deposit_amount {
                return Err(WithdrawalProofError::GenesisBalanceMismatch);
            }
            // state_sig_epoch must be 0.
            if self.state_sig_epoch != 0 {
                return Err(WithdrawalProofError::GenesisEpochNonZero);
            }
            // state_sig_root must be 0.
            if !self.state_sig_root.is_zero() {
                return Err(WithdrawalProofError::GenesisRootNonZero);
            }
        } else {
            // Non-genesis: state_sig_epoch > 0, state_sig_root != 0.
            if self.state_sig_epoch == 0 {
                return Err(WithdrawalProofError::NonGenesisEpochZero);
            }
            if self.state_sig_root.is_zero() {
                return Err(WithdrawalProofError::NonGenesisRootZero);
            }
            // Structural checks live here; full XMSS verification is performed
            // by validate_with_signatures once the private signature is supplied.
        }

        // 7. final_balance <= deposit_amount.
        if self.final_balance > self.deposit_amount {
            return Err(WithdrawalProofError::BalanceExceedsDeposit {
                final_balance: self.final_balance,
                deposit_amount: self.deposit_amount,
            });
        }

        // 8-9. Clearance constraints.
        if self.has_clearance {
            if self.clear_sig_epoch == 0 {
                return Err(WithdrawalProofError::ClearanceEpochZero);
            }
            if self.clear_sig_root.is_zero() {
                return Err(WithdrawalProofError::ClearanceRootZero);
            }
            // Structural checks live here; full XMSS clearance verification is
            // performed by validate_with_signatures once the signature is supplied.
        } else {
            if self.clear_sig_epoch != 0 {
                return Err(WithdrawalProofError::NoClearanceEpochNonZero);
            }
            if !self.clear_sig_root.is_zero() {
                return Err(WithdrawalProofError::NoClearanceRootNonZero);
            }
        }

        Ok(())
    }

    /// Run all local checks including XMSS verification for state/clearance signatures.
    pub fn validate_with_signatures(
        &self,
        state_sig: Option<&XmssSignature>,
        clear_sig: Option<&XmssSignature>,
    ) -> Result<(), WithdrawalProofError> {
        self.validate()?;

        if self.is_genesis {
            if state_sig.is_some() {
                return Err(WithdrawalProofError::UnexpectedStateSignature);
            }
        } else {
            let sig = state_sig.ok_or(WithdrawalProofError::MissingStateSignature)?;
            if sig.epoch != self.state_sig_epoch {
                return Err(WithdrawalProofError::StateSignatureEpochMismatch {
                    expected: self.state_sig_epoch,
                    actual: sig.epoch,
                });
            }
            validate_xmss_signature(sig).map_err(WithdrawalProofError::StateSignatureInvalid)?;

            let commitment = PedersenCommitment::commit(self.final_balance, &self.final_blinding);
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
                return Err(WithdrawalProofError::StateSignatureInvalid(
                    "XMSS root/path verification failed".to_string(),
                ));
            }
        }

        if self.has_clearance {
            let sig = clear_sig.ok_or(WithdrawalProofError::MissingClearanceSignature)?;
            if sig.epoch != self.clear_sig_epoch {
                return Err(WithdrawalProofError::ClearanceSignatureEpochMismatch {
                    expected: self.clear_sig_epoch,
                    actual: sig.epoch,
                });
            }
            validate_xmss_signature(sig)
                .map_err(WithdrawalProofError::ClearanceSignatureInvalid)?;

            let nullifier = self.nullifier();
            let clear_msg = compute_clearance_message(
                self.protocol_version,
                self.chain_id,
                &self.contract_address,
                &nullifier,
            );
            if !verify_xmss_signature(&self.clear_sig_root, &clear_msg, sig) {
                return Err(WithdrawalProofError::ClearanceSignatureInvalid(
                    "XMSS root/path verification failed".to_string(),
                ));
            }
        } else if clear_sig.is_some() {
            return Err(WithdrawalProofError::UnexpectedClearanceSignature);
        }

        Ok(())
    }

    /// Build a serialized witness envelope that the verifier can re-run locally.
    #[cfg(feature = "dev-witness-envelope")]
    pub fn build_envelope(
        &self,
        state_sig: Option<&XmssSignature>,
        clear_sig: Option<&XmssSignature>,
    ) -> Result<WithdrawalProofEnvelope, WithdrawalProofError> {
        self.validate_with_signatures(state_sig, clear_sig)?;

        Ok(WithdrawalProofEnvelope {
            public_inputs: self.build_public_inputs(),
            secret_s: self.secret_s,
            deposit_amount: self.deposit_amount,
            expiry_ts: self.expiry_ts,
            merkle_siblings: self.merkle_siblings,
            final_blinding: field_to_felt(&self.final_blinding),
            current_anchor: self.current_anchor,
            state_sig: state_sig.cloned(),
            clear_sig: clear_sig.cloned(),
        })
    }

    /// Serialize the proof envelope as JSON bytes.
    #[cfg(feature = "dev-witness-envelope")]
    pub fn generate_proof(
        &self,
        state_sig: Option<&XmssSignature>,
        clear_sig: Option<&XmssSignature>,
    ) -> Result<Vec<u8>, WithdrawalProofError> {
        let envelope = self.build_envelope(state_sig, clear_sig)?;
        serde_json::to_vec(&envelope)
            .map_err(|e| WithdrawalProofError::Serialization(e.to_string()))
    }

    // -- mock proof ----------------------------------------------------

    /// Produce a mock proof blob for testing.
    ///
    /// In a production build this would invoke the Cairo STARK prover.
    pub fn generate_mock_proof(&self) -> Vec<u8> {
        MOCK_PROOF_ENVELOPE.to_vec()
    }
}

/// Verify a serialized withdrawal proof envelope against expected public inputs.
#[cfg(feature = "dev-witness-envelope")]
pub fn verify_withdrawal_proof(
    proof: &[u8],
    expected_inputs: &WithdrawalPublicInputs,
) -> Result<(), WithdrawalProofError> {
    let envelope: WithdrawalProofEnvelope = serde_json::from_slice(proof)
        .map_err(|e| WithdrawalProofError::Serialization(e.to_string()))?;
    if &envelope.public_inputs != expected_inputs {
        return Err(WithdrawalProofError::PublicInputsMismatch);
    }

    let builder = WithdrawalProofBuilder::new(
        envelope.secret_s,
        expected_inputs.note_id,
        envelope.deposit_amount,
        envelope.expiry_ts,
        envelope.merkle_siblings,
        expected_inputs.final_balance,
        felt_to_field(&envelope.final_blinding),
        envelope.current_anchor,
        expected_inputs.is_genesis,
        expected_inputs.state_sig_epoch,
        expected_inputs.state_sig_root,
        expected_inputs.has_clearance,
        expected_inputs.clear_sig_epoch,
        expected_inputs.clear_sig_root,
        expected_inputs.destination,
        expected_inputs.active_root,
        expected_inputs.protocol_version,
        expected_inputs.chain_id,
        expected_inputs.contract_address,
    );

    let rebuilt_inputs = builder.build_public_inputs();
    if &rebuilt_inputs != expected_inputs {
        return Err(WithdrawalProofError::PublicInputsMismatch);
    }

    builder.validate_with_signatures(envelope.state_sig.as_ref(), envelope.clear_sig.as_ref())
}

// Validate the XMSS signature structurally at the height committed by the
// signature itself; see the matching note in `request.rs`. The deployment
// height is configurable and bound into the trusted signing root, so we honor
// the root-committed height instead of mandating `XMSS_TREE_HEIGHT`.
fn validate_xmss_signature(sig: &XmssSignature) -> Result<(), String> {
    let height = sig.auth_path.len();
    if height == 0 || height > XMSS_TREE_HEIGHT {
        return Err(format!(
            "XMSS auth path height must be between 1 and {XMSS_TREE_HEIGHT}, got {height}"
        ));
    }
    sig.validate_for_height(height)
}

fn verify_xmss_signature(root: &Felt252, message: &Felt252, sig: &XmssSignature) -> bool {
    XmssVerifier::verify(root, message, sig)
}

fn merkle_index_bits(index: u32) -> impl Iterator<Item = Felt252> {
    (0..MERKLE_DEPTH).map(move |level| Felt252::from_u64(((index >> level) & 1) as u64))
}

fn append_signature_args(args: &mut Vec<Felt252>, sig: Option<&XmssSignature>) {
    if let Some(sig) = sig {
        args.push(Felt252::from_u64(sig.leaf_index as u64));
        args.extend(sig.wots_sig.iter().copied());
        args.push(Felt252::from_u64(sig.auth_path.len() as u64));
        args.extend(sig.auth_path.iter().copied());
        args.extend(std::iter::repeat_n(
            Felt252::ZERO,
            XMSS_TREE_HEIGHT - sig.auth_path.len(),
        ));
    } else {
        args.push(Felt252::ZERO);
        args.extend(std::iter::repeat_n(Felt252::ZERO, WOTS_LEN));
        args.push(Felt252::ZERO);
        args.extend(std::iter::repeat_n(Felt252::ZERO, XMSS_TREE_HEIGHT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dev-witness-envelope")]
    use zkapi_core::commitment::{compute_clearance_message, compute_state_message};
    use zkapi_core::merkle::MerkleTree;
    #[cfg(feature = "dev-witness-envelope")]
    use zkapi_crypto::xmss::XmssKeypair;

    /// Helper: build a minimal genesis withdrawal witness that passes validation.
    fn genesis_builder() -> WithdrawalProofBuilder {
        let secret = Felt252::from_u64(42);
        let deposit = 1_000u128;
        let expiry = 1_700_000_000u64;

        let c = compute_registration_commitment(&secret);
        let leaf = compute_note_leaf(0, &c, deposit, expiry);
        let mut tree = MerkleTree::new();
        tree.insert(leaf);
        let siblings = tree.get_siblings(0);
        let root = tree.root();

        let destination = [
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        WithdrawalProofBuilder::new(
            secret,
            0, // note_id
            deposit,
            expiry,
            siblings,
            deposit,                           // final_balance == deposit for genesis
            FieldElement::ZERO,                // final_blinding
            Felt252::from_u64(GENESIS_ANCHOR), // current_anchor = 1
            true,                              // is_genesis
            0,                                 // state_sig_epoch
            Felt252::ZERO,                     // state_sig_root
            false,                             // has_clearance
            0,                                 // clear_sig_epoch
            Felt252::ZERO,                     // clear_sig_root
            destination,
            root,                      // active_root
            1,                         // protocol_version
            1,                         // chain_id
            Felt252::from_u64(0xdead), // contract_address
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
        let pi = builder.build_public_inputs();
        assert_eq!(pi.statement_type, STATEMENT_TYPE_WITHDRAWAL);
        assert_eq!(pi.protocol_version, 1);
        assert_eq!(pi.chain_id, 1);
        assert_eq!(pi.note_id, 0);
        assert_eq!(pi.final_balance, 1_000);
        assert!(!pi.withdrawal_nullifier.is_zero());
        assert!(pi.is_genesis);
        assert!(!pi.has_clearance);
    }

    #[test]
    fn test_cairo_args_for_genesis_withdrawal() {
        let builder = genesis_builder();
        let args = builder.to_cairo_args(None, None).unwrap();
        assert_eq!(args.len(), 256);
        assert_eq!(args[0], Felt252::from_u64(1));
        assert_eq!(args[9], Felt252::ZERO);
        assert_eq!(args[76], Felt252::ONE);
        assert_eq!(args[79], Felt252::ZERO);
        assert_eq!(args[145], Felt252::ZERO);
        assert_eq!(args[166], Felt252::ZERO);
        assert_eq!(args[169], Felt252::ZERO);
        assert_eq!(args[235], Felt252::ZERO);
    }

    #[test]
    fn test_balance_exceeds_deposit() {
        let mut builder = genesis_builder();
        // Need to set both balances so genesis constraint still holds first;
        // easiest: break the genesis balance match and see that error, so
        // instead test on non-genesis path.
        builder.is_genesis = false;
        builder.state_sig_epoch = 1;
        builder.state_sig_root = Felt252::from_u64(0xabc);
        builder.current_anchor = Felt252::from_u64(99);
        builder.final_balance = builder.deposit_amount + 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(
            err,
            WithdrawalProofError::BalanceExceedsDeposit { .. }
        ));
    }

    #[test]
    fn test_genesis_anchor_mismatch() {
        let mut builder = genesis_builder();
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::GenesisAnchorMismatch));
    }

    #[test]
    fn test_genesis_balance_mismatch() {
        let mut builder = genesis_builder();
        builder.final_balance = builder.deposit_amount - 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::GenesisBalanceMismatch));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let mut builder = genesis_builder();
        builder.merkle_siblings[0] = Felt252::from_u64(0xbad);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::MerkleProofInvalid));
    }

    #[test]
    fn test_clearance_epoch_zero() {
        let mut builder = genesis_builder();
        builder.has_clearance = true;
        builder.clear_sig_epoch = 0;
        builder.clear_sig_root = Felt252::from_u64(0xabc);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::ClearanceEpochZero));
    }

    #[test]
    fn test_clearance_root_zero() {
        let mut builder = genesis_builder();
        builder.has_clearance = true;
        builder.clear_sig_epoch = 1;
        builder.clear_sig_root = Felt252::ZERO;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::ClearanceRootZero));
    }

    #[test]
    fn test_no_clearance_epoch_nonzero() {
        let mut builder = genesis_builder();
        builder.has_clearance = false;
        builder.clear_sig_epoch = 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::NoClearanceEpochNonZero));
    }

    #[test]
    fn test_no_clearance_root_nonzero() {
        let mut builder = genesis_builder();
        builder.has_clearance = false;
        builder.clear_sig_root = Felt252::from_u64(0xabc);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::NoClearanceRootNonZero));
    }

    #[test]
    fn test_non_genesis_epoch_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.state_sig_epoch = 0;
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::NonGenesisEpochZero));
    }

    #[test]
    fn test_non_genesis_root_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.state_sig_epoch = 1;
        builder.state_sig_root = Felt252::ZERO;
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, WithdrawalProofError::NonGenesisRootZero));
    }

    #[test]
    fn test_mock_proof_generation() {
        let builder = genesis_builder();
        let proof = builder.generate_mock_proof();
        assert_eq!(proof.len(), 32);
        assert!(proof.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_nullifier_deterministic() {
        let builder = genesis_builder();
        let n1 = builder.nullifier();
        let n2 = builder.nullifier();
        assert_eq!(n1, n2);
        assert!(!n1.is_zero());
    }

    #[cfg(feature = "dev-witness-envelope")]
    #[test]
    fn test_real_proof_roundtrip_with_clearance() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.final_balance = 900;
        builder.final_blinding = FieldElement::from(9u64);
        builder.current_anchor = Felt252::from_u64(55);
        builder.has_clearance = true;

        let state_keypair = XmssKeypair::generate_with_height(&FieldElement::from(123u64), 4);
        builder.state_sig_epoch = 7;
        builder.state_sig_root = state_keypair.root_felt();

        let clear_keypair = XmssKeypair::generate_with_height(&FieldElement::from(456u64), 4);
        builder.clear_sig_epoch = 8;
        builder.clear_sig_root = clear_keypair.root_felt();

        let commitment = PedersenCommitment::commit(builder.final_balance, &builder.final_blinding);
        let (cx, cy) = commitment.to_affine();
        let state_msg = compute_state_message(
            builder.protocol_version,
            builder.chain_id,
            &builder.contract_address,
            &field_to_felt(&cx),
            &field_to_felt(&cy),
            &builder.current_anchor,
        );
        let (mut state_sig, _) = state_keypair.sign(&state_msg).unwrap();
        state_sig.epoch = builder.state_sig_epoch;

        let clear_msg = compute_clearance_message(
            builder.protocol_version,
            builder.chain_id,
            &builder.contract_address,
            &builder.nullifier(),
        );
        let (mut clear_sig, _) = clear_keypair.sign(&clear_msg).unwrap();
        clear_sig.epoch = builder.clear_sig_epoch;

        let public_inputs = builder.build_public_inputs();
        let proof = builder
            .generate_proof(Some(&state_sig), Some(&clear_sig))
            .unwrap();
        verify_withdrawal_proof(&proof, &public_inputs).unwrap();
    }
}
