//! Main wallet implementation tying together note state, proof generation,
//! server communication, and atomic persistence.
//!
//! Implements the full client flows from spec sections 10.2-10.5:
//! - deposit  (10.2)
//! - request  (10.3)
//! - recovery (10.4)
//! - withdrawal -- mutual close and escape hatch (10.5)

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::Rng;
use zkapi_core::poseidon::FieldElement;

use zkapi_core::commitment::{compute_clearance_message, compute_state_message};
use zkapi_core::leaf::compute_registration_commitment;
use zkapi_core::nullifier::compute_nullifier;
use zkapi_core::poseidon::{felt_to_field, field_to_felt};
use zkapi_crypto::{
    pedersen::{add_blinding, PedersenCommitment},
    xmss::XmssVerifier,
};
use zkapi_proof::{ProofArtifact, RequestProofBuilder, ScarbStwoProver, WithdrawalProofBuilder};
use zkapi_types::wire::{
    ApiRequest, ClearanceRequest, ClearanceResponse, ErrorResponse, ProofArtifactWire,
    ProofBackendWire, RecoveryResponse, RequestResponse,
};
use zkapi_types::{
    canonical_payload_hash, canonical_response_hash, lookup_clear_root, lookup_state_root, Felt252,
    RequestPublicInputs, WithdrawalPublicInputs, MERKLE_DEPTH, STATEMENT_TYPE_REQUEST,
    STATEMENT_TYPE_WITHDRAWAL,
};

use crate::config::{ClientConfig, ClientProofMode};
use crate::error::ClientError;
use crate::journal::PendingRequestJournal;
use crate::note_state::NoteState;

/// The client wallet.
///
/// Manages one note at a time: persists state to disk, generates proofs,
/// communicates with the server, and verifies responses.
pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    http: reqwest::Client,
}

impl Wallet {
    /// Create a new wallet instance.
    ///
    /// If a state file already exists on disk it is loaded automatically.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let state_dir = PathBuf::from(&config.state_dir);
        std::fs::create_dir_all(&state_dir)?;

        let state_path = state_dir.join("note_state.json");
        let journal_path = state_dir.join("pending_journal.json");

        let state = if state_path.exists() {
            Some(NoteState::load(&state_path)?)
        } else {
            None
        };

        Ok(Self {
            config,
            state,
            state_path,
            journal_path,
            http: reqwest::Client::new(),
        })
    }

    /// Return a reference to the current note state, if one is active.
    pub fn state(&self) -> Option<&NoteState> {
        self.state.as_ref()
    }

    /// Check whether a pending request journal exists on disk.
    pub fn has_pending_request(&self) -> bool {
        PendingRequestJournal::read(&self.journal_path)
            .ok()
            .flatten()
            .is_some()
    }

    // ------------------------------------------------------------------
    // Deposit flow (spec 10.2)
    // ------------------------------------------------------------------

    /// Execute the deposit flow.
    ///
    /// 1. Sample a random nonzero secret `s`.
    /// 2. Compute the registration commitment `C = Poseidon(DOMAIN_REG, s, 0)`.
    /// 3. Compute the initial Pedersen commitment `E(deposit_amount, r0)` with
    ///    random blinding `r0`.
    /// 4. Create a genesis `NoteState` and persist it.
    ///
    /// Returns `(secret_s, registration_commitment)`. The caller is
    /// responsible for submitting the on-chain `deposit` transaction using
    /// the returned commitment.
    pub fn generate_deposit_params(&self) -> (Felt252, Felt252) {
        let mut rng = rand::thread_rng();
        let secret_s = sample_nonzero_felt(&mut rng);
        let commitment = compute_registration_commitment(&secret_s);
        (secret_s, commitment)
    }

    /// Confirm a deposit after the on-chain transaction has landed.
    ///
    /// Creates and persists the genesis `NoteState`.
    pub fn confirm_deposit(
        &mut self,
        secret_s: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry_ts: u64,
    ) -> Result<(), ClientError> {
        if self.state.is_some() {
            return Err(ClientError::NoteAlreadyExists);
        }

        // Sample initial blinding factor.
        let mut rng = rand::thread_rng();
        let r0 = sample_field_element(&mut rng);

        // Compute initial commitment E(deposit_amount, r0).
        let commitment = PedersenCommitment::commit(deposit_amount, &r0);
        let (cx, cy) = commitment.to_affine();

        let blinding_hex = format!("0x{}", hex::encode(r0.to_bytes_be()));

        let note_state = NoteState::new_from_deposit(
            self.config.protocol_version,
            self.config.chain_id,
            self.config.contract_address,
            note_id,
            secret_s,
            deposit_amount,
            expiry_ts,
            blinding_hex,
            field_to_felt(&cx),
            field_to_felt(&cy),
        );

        // Persist atomically.
        note_state.save(&self.state_path)?;
        self.state = Some(note_state);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Request flow (spec 10.3)
    // ------------------------------------------------------------------

    /// Build a request, write the journal, send it to the server, verify the
    /// response, and update local state.
    ///
    /// `payload` is the raw API request body. `payload_hash` is its
    /// protocol-defined hash. `active_root` and `merkle_siblings` come from
    /// the indexer.
    ///
    /// Returns the `RequestResponse` from the server on success.
    pub async fn request_flow(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<RequestResponse, ClientError> {
        // 1. Check no pending journal exists.
        if PendingRequestJournal::read(&self.journal_path)?.is_some() {
            return Err(ClientError::PendingRequest);
        }
        let actual_payload_hash = canonical_payload_hash(payload.as_bytes());
        if payload_hash != actual_payload_hash {
            return Err(ClientError::InvalidResponse(
                "payload_hash does not match actual payload bytes".into(),
            ));
        }

        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let mut rng = rand::thread_rng();

        // Check balance is sufficient for the solvency bound.
        let solvency = state.solvency_bound(
            self.config.policy_enabled,
            self.config.request_charge_cap,
            self.config.policy_charge_cap,
        );
        if state.current_balance < solvency {
            return Err(ClientError::InsufficientBalance {
                needed: solvency,
                available: state.current_balance,
            });
        }

        // 2. Build request proof inputs.
        let current_blinding = parse_blinding(&state.balance_blinding)?;
        let user_rerandomization = sample_field_element(&mut rng);
        let siblings = siblings_from_vec(merkle_siblings)?;

        // Compute anon_commitment = E(current_balance, current_blinding + user_rerand).
        let anon_blinding = add_blinding(&current_blinding, &user_rerandomization);
        let anon_commitment = PedersenCommitment::commit(state.current_balance, &anon_blinding);
        let (anon_cx, anon_cy) = anon_commitment.to_affine();

        // Compute nullifier = Poseidon(DOMAIN_NULL, secret_s, current_anchor).
        let request_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            (
                state.state_sig_epoch.ok_or_else(|| {
                    ClientError::ProofGeneration("missing state_sig_epoch".into())
                })?,
                state
                    .state_sig_root
                    .ok_or_else(|| ClientError::ProofGeneration("missing state_sig_root".into()))?,
            )
        };

        let public_inputs = RequestPublicInputs {
            statement_type: STATEMENT_TYPE_REQUEST,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_sig_epoch,
            state_sig_root,
            request_nullifier,
            anon_commitment_x: field_to_felt(&anon_cx),
            anon_commitment_y: field_to_felt(&anon_cy),
            expiry_ts: state.expiry_ts,
            solvency_bound: solvency,
        };

        let proof_builder = RequestProofBuilder::new(
            state.secret_s,
            state.note_id,
            state.deposit_amount,
            state.expiry_ts,
            siblings,
            state.current_balance,
            current_blinding,
            user_rerandomization,
            state.current_anchor,
            state.is_genesis,
            state_sig_epoch,
            state_sig_root,
            active_root,
            state.protocol_version,
            state.chain_id,
            state.contract_address,
            solvency,
        );
        let proof =
            self.generate_request_proof_artifact(&proof_builder, state.state_sig.as_ref())?;

        // 4. Write journal.
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: client_request_id.clone(),
            nullifier: request_nullifier,
            payload_hash,
            user_rerandomization: field_to_felt(&user_rerandomization),
            created_at_ms: now_ms(),
        };
        PendingRequestJournal::write(&self.journal_path, &journal)?;

        // 5. Send request to server.
        let api_request = ApiRequest {
            client_request_id: client_request_id.clone(),
            payload: payload.to_string(),
            payload_hash,
            public_inputs,
            proof,
        };

        let url = format!("{}/v1/requests", self.config.server_url);
        let resp = self
            .http
            .post(&url)
            .json(&api_request)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let status_code = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        if !status_code.is_success() {
            // Try to parse structured error response.
            if let Ok(err_resp) = serde_json::from_str::<ErrorResponse>(&body) {
                // Per spec 10.4: if stale_root the nullifier was never reserved,
                // so the client may clear the journal and retry.
                if err_resp.error_code == "stale_root" {
                    PendingRequestJournal::clear(&self.journal_path)?;
                    return Err(ClientError::StaleRoot);
                }
                return Err(ClientError::ServerError(format!(
                    "{}: {}",
                    err_resp.error_code, err_resp.error_message
                )));
            }
            return Err(ClientError::ServerError(format!(
                "HTTP {}: {}",
                status_code, body
            )));
        }

        let server_resp: RequestResponse =
            serde_json::from_str(&body).map_err(|e| ClientError::InvalidResponse(e.to_string()))?;

        // 6. Verify response.
        self.verify_request_response(
            &server_resp,
            &anon_commitment,
            &user_rerandomization,
            &current_blinding,
        )?;

        // 7. Update state:
        //    nextBalance = currentBalance - charge
        //    nextBlinding = currentBlinding + user_rerandomization + blind_delta_srv
        let charge = server_resp.charge_applied;
        let next_balance = state
            .current_balance
            .checked_sub(charge)
            .ok_or_else(|| ClientError::InvalidResponse("charge exceeds balance".into()))?;

        let blind_delta_srv = felt_to_field(&server_resp.blind_delta_srv);
        let next_blinding = add_blinding(
            &add_blinding(&current_blinding, &user_rerandomization),
            &blind_delta_srv,
        );
        let next_blinding_hex = format!("0x{}", hex::encode(next_blinding.to_bytes_be()));

        let mut next_state = state.clone();
        next_state.current_balance = next_balance;
        next_state.balance_blinding = next_blinding_hex;
        next_state.current_commitment_x = server_resp.next_commitment.x;
        next_state.current_commitment_y = server_resp.next_commitment.y;
        next_state.current_anchor = server_resp.next_anchor;
        next_state.is_genesis = false;
        next_state.state_sig_epoch = Some(server_resp.next_state_sig_epoch);
        next_state.state_sig_root = Some(server_resp.next_state_sig_root);
        next_state.state_sig = Some(server_resp.next_state_sig.clone());

        // 8. Save new state atomically.
        next_state.save(&self.state_path)?;
        self.state = Some(next_state);

        // 9. Clear journal.
        PendingRequestJournal::clear(&self.journal_path)?;

        Ok(server_resp)
    }

    fn generate_request_proof_artifact(
        &self,
        builder: &RequestProofBuilder,
        state_sig: Option<&zkapi_types::XmssSignature>,
    ) -> Result<ProofArtifactWire, ClientError> {
        match &self.config.proof_mode {
            ClientProofMode::StwoScarb { cairo_dir } => {
                let public_inputs = builder
                    .build_public_inputs()
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                let args = builder
                    .to_cairo_args(state_sig)
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                let artifact = ScarbStwoProver::new(cairo_dir)
                    .prove_and_verify_executable_with_args(
                        "request_from_args",
                        public_inputs.public_output_hash(),
                        &args,
                    )
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                Ok(proof_artifact_to_wire(artifact))
            }
            #[cfg(feature = "dev-witness-envelope")]
            ClientProofMode::DevWitnessEnvelope => {
                let proof = builder
                    .generate_proof(state_sig)
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                let public_inputs = builder
                    .build_public_inputs()
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                Ok(ProofArtifactWire {
                    backend: ProofBackendWire::StwoCairo,
                    public_output_hash: public_inputs.public_output_hash(),
                    proof: base64::engine::general_purpose::STANDARD.encode(proof),
                })
            }
        }
    }

    fn generate_withdrawal_proof_artifact(
        &self,
        builder: &WithdrawalProofBuilder,
        state_sig: Option<&zkapi_types::XmssSignature>,
        clear_sig: Option<&zkapi_types::XmssSignature>,
    ) -> Result<ProofArtifactWire, ClientError> {
        match &self.config.proof_mode {
            ClientProofMode::StwoScarb { cairo_dir } => {
                let public_inputs = builder.build_public_inputs();
                let args = builder
                    .to_cairo_args(state_sig, clear_sig)
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                let artifact = ScarbStwoProver::new(cairo_dir)
                    .prove_and_verify_executable_with_args(
                        "withdrawal_from_args",
                        public_inputs.public_output_hash(),
                        &args,
                    )
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                Ok(proof_artifact_to_wire(artifact))
            }
            #[cfg(feature = "dev-witness-envelope")]
            ClientProofMode::DevWitnessEnvelope => {
                let proof = builder
                    .generate_proof(state_sig, clear_sig)
                    .map_err(|e| ClientError::ProofGeneration(e.to_string()))?;
                let public_inputs = builder.build_public_inputs();
                Ok(ProofArtifactWire {
                    backend: ProofBackendWire::StwoCairo,
                    public_output_hash: public_inputs.public_output_hash(),
                    proof: base64::engine::general_purpose::STANDARD.encode(proof),
                })
            }
        }
    }

    /// Verify the server's request response (spec 10.3 step 8).
    ///
    /// Checks:
    /// - `charge_applied <= configured cap`
    /// - commitment algebra: `next_commitment == anon - charge*G + blind_delta*H`
    /// - state signature structural validity
    fn verify_request_response(
        &self,
        resp: &RequestResponse,
        anon_commitment: &PedersenCommitment,
        _user_rerandomization: &FieldElement,
        _current_blinding: &FieldElement,
    ) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;

        let expected_response_hash = canonical_response_hash(resp.response_payload.as_bytes());
        if resp.response_hash != expected_response_hash {
            return Err(ClientError::VerificationFailed(
                "response_hash does not match response_payload".into(),
            ));
        }

        // Check charge bound.
        let max_charge = if self.config.policy_enabled {
            self.config.policy_charge_cap
        } else {
            self.config.request_charge_cap
        };
        if resp.charge_applied > max_charge {
            return Err(ClientError::VerificationFailed(format!(
                "charge {} exceeds cap {}",
                resp.charge_applied, max_charge
            )));
        }

        // Check next_anchor is not zero (spec 9.4).
        if resp.next_anchor.is_zero() {
            return Err(ClientError::InvalidResponse("zero next anchor".into()));
        }

        // Verify commitment algebra:
        //   expected_next = anon_commitment - charge * G_balance + blind_delta * H_blind
        let blind_delta = felt_to_field(&resp.blind_delta_srv);
        let expected = PedersenCommitment::server_update(
            &anon_commitment.point,
            resp.charge_applied,
            &blind_delta,
        );
        let (exp_x, exp_y) = expected.to_affine();
        let exp_x_felt = field_to_felt(&exp_x);
        let exp_y_felt = field_to_felt(&exp_y);

        if exp_x_felt != resp.next_commitment.x || exp_y_felt != resp.next_commitment.y {
            return Err(ClientError::VerificationFailed(
                "next_commitment algebra mismatch".into(),
            ));
        }

        // Verify the state signature structural validity at the root-committed
        // height (the operator's `xmss_height` is bound into the trusted signing
        // root; see the note in `zkapi-proof/src/request.rs`).
        if let Err(e) = resp
            .next_state_sig
            .validate_for_height(resp.next_state_sig.auth_path.len())
        {
            return Err(ClientError::VerificationFailed(format!(
                "state sig structural check failed: {}",
                e
            )));
        }
        if resp.next_state_sig_epoch == 0 || resp.next_state_sig_root.is_zero() {
            return Err(ClientError::InvalidResponse(
                "missing non-genesis state signature root/epoch".into(),
            ));
        }
        match lookup_state_root(&self.config.trusted_epoch_roots, resp.next_state_sig_epoch) {
            Some(root) if root == resp.next_state_sig_root => {}
            Some(_) => {
                return Err(ClientError::VerificationFailed(
                    "state signature root does not match trusted epoch registry".into(),
                ));
            }
            None => {
                return Err(ClientError::VerificationFailed(
                    "state signature epoch is not trusted".into(),
                ));
            }
        }
        if resp.next_state_sig.epoch != resp.next_state_sig_epoch {
            return Err(ClientError::VerificationFailed(format!(
                "state sig epoch mismatch: {} != {}",
                resp.next_state_sig.epoch, resp.next_state_sig_epoch
            )));
        }

        // Compute the state message that should have been signed.
        // In production the client would fetch the XMSS root for the returned
        // epoch from the indexer / on-chain and verify the full XMSS signature.
        let state_msg = compute_state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &resp.next_commitment.x,
            &resp.next_commitment.y,
            &resp.next_anchor,
        );

        if !XmssVerifier::verify(&resp.next_state_sig_root, &state_msg, &resp.next_state_sig) {
            return Err(ClientError::VerificationFailed(
                "state signature XMSS verification failed".into(),
            ));
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Withdrawal flow -- mutual close (spec 10.5)
    // ------------------------------------------------------------------

    /// Execute a mutual-close withdrawal.
    ///
    /// 1. Compute withdrawal nullifier.
    /// 2. Request clearance from server.
    /// 3. Build withdrawal proof with `has_clearance = true`.
    /// 4. Return `(WithdrawalPublicInputs, proof_artifact)` for on-chain submission.
    pub async fn withdrawal_mutual_close(
        &mut self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputs, ProofArtifactWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let siblings = siblings_from_vec(merkle_siblings)?;

        // 1. Compute withdrawal_nullifier.
        let withdrawal_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        // 2. Request clearance from server.
        let clearance = self.request_clearance(&withdrawal_nullifier).await?;

        // 3. Build withdrawal proof with has_clearance = true.
        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            (
                state.state_sig_epoch.ok_or_else(|| {
                    ClientError::ProofGeneration("missing state_sig_epoch".into())
                })?,
                state
                    .state_sig_root
                    .ok_or_else(|| ClientError::ProofGeneration("missing state_sig_root".into()))?,
            )
        };

        let public_inputs = WithdrawalPublicInputs {
            statement_type: STATEMENT_TYPE_WITHDRAWAL,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            note_id: state.note_id,
            final_balance: state.current_balance,
            destination,
            withdrawal_nullifier,
            is_genesis: state.is_genesis,
            has_clearance: true,
            state_sig_epoch,
            state_sig_root,
            clear_sig_epoch: clearance.clear_sig_epoch,
            clear_sig_root: clearance.clear_sig_root,
        };

        let current_blinding = parse_blinding(&state.balance_blinding)?;
        let proof_builder = WithdrawalProofBuilder::new(
            state.secret_s,
            state.note_id,
            state.deposit_amount,
            state.expiry_ts,
            siblings,
            state.current_balance,
            current_blinding,
            state.current_anchor,
            state.is_genesis,
            state_sig_epoch,
            state_sig_root,
            true,
            clearance.clear_sig_epoch,
            clearance.clear_sig_root,
            destination,
            active_root,
            state.protocol_version,
            state.chain_id,
            state.contract_address,
        );
        let proof = self.generate_withdrawal_proof_artifact(
            &proof_builder,
            state.state_sig.as_ref(),
            Some(&clearance.clear_sig),
        )?;

        Ok((public_inputs, proof))
    }

    // ------------------------------------------------------------------
    // Withdrawal flow -- escape hatch (spec 10.5)
    // ------------------------------------------------------------------

    /// Execute an escape-hatch withdrawal (no server clearance).
    ///
    /// Returns `(WithdrawalPublicInputs, proof_artifact)` for on-chain
    /// `initiateEscapeWithdrawal`.
    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputs, ProofArtifactWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let siblings = siblings_from_vec(merkle_siblings)?;

        // 1. Compute withdrawal_nullifier.
        let withdrawal_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            (
                state.state_sig_epoch.ok_or_else(|| {
                    ClientError::ProofGeneration("missing state_sig_epoch".into())
                })?,
                state
                    .state_sig_root
                    .ok_or_else(|| ClientError::ProofGeneration("missing state_sig_root".into()))?,
            )
        };

        // 2. Build withdrawal proof with has_clearance = false.
        let public_inputs = WithdrawalPublicInputs {
            statement_type: STATEMENT_TYPE_WITHDRAWAL,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            note_id: state.note_id,
            final_balance: state.current_balance,
            destination,
            withdrawal_nullifier,
            is_genesis: state.is_genesis,
            has_clearance: false,
            state_sig_epoch,
            state_sig_root,
            clear_sig_epoch: 0,
            clear_sig_root: Felt252::ZERO,
        };

        let current_blinding = parse_blinding(&state.balance_blinding)?;
        let proof_builder = WithdrawalProofBuilder::new(
            state.secret_s,
            state.note_id,
            state.deposit_amount,
            state.expiry_ts,
            siblings,
            state.current_balance,
            current_blinding,
            state.current_anchor,
            state.is_genesis,
            state_sig_epoch,
            state_sig_root,
            false,
            0,
            Felt252::ZERO,
            destination,
            active_root,
            state.protocol_version,
            state.chain_id,
            state.contract_address,
        );
        let proof = self.generate_withdrawal_proof_artifact(
            &proof_builder,
            state.state_sig.as_ref(),
            None,
        )?;

        Ok((public_inputs, proof))
    }

    /// Archive the note state after a successful close.
    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = self.state.take() {
            state.archive(&self.state_path)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Recovery (spec 10.4)
    // ------------------------------------------------------------------

    /// Attempt to recover from a pending request journal.
    ///
    /// 1. Check if journal exists.
    /// 2. Query server recovery endpoint.
    /// 3. If finalized, verify and install the returned next state.
    /// 4. If reserved, return error indicating retry needed.
    pub async fn recover(&mut self) -> Result<Option<RequestResponse>, ClientError> {
        // 1. Check if journal exists.
        let journal = match PendingRequestJournal::read(&self.journal_path)? {
            Some(j) => j,
            None => return Ok(None), // nothing to recover
        };

        // 2. Query server recovery endpoint.
        let url = format!(
            "{}/v1/requests/{}",
            self.config.server_url, journal.client_request_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let recovery: RecoveryResponse =
            serde_json::from_str(&body).map_err(|e| ClientError::InvalidResponse(e.to_string()))?;

        match recovery.nullifier_status.as_str() {
            "finalized" => {
                // 3. If finalized, verify and install state.
                let server_resp = recovery.request_response.ok_or_else(|| {
                    ClientError::InvalidResponse(
                        "finalized recovery missing request_response".into(),
                    )
                })?;

                let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
                let user_rerandomization = felt_to_field(&journal.user_rerandomization);
                let current_blinding = parse_blinding(&state.balance_blinding)?;
                let anon_blinding = add_blinding(&current_blinding, &user_rerandomization);
                let anon_commitment =
                    PedersenCommitment::commit(state.current_balance, &anon_blinding);

                self.verify_request_response(
                    &server_resp,
                    &anon_commitment,
                    &user_rerandomization,
                    &current_blinding,
                )?;

                let charge = server_resp.charge_applied;
                let next_balance = state
                    .current_balance
                    .checked_sub(charge)
                    .ok_or_else(|| ClientError::InvalidResponse("charge exceeds balance".into()))?;

                let blind_delta_srv = felt_to_field(&server_resp.blind_delta_srv);
                let next_blinding = add_blinding(
                    &add_blinding(&current_blinding, &user_rerandomization),
                    &blind_delta_srv,
                );
                let next_blinding_hex = format!("0x{}", hex::encode(next_blinding.to_bytes_be()));

                let mut next_state = state.clone();
                next_state.current_balance = next_balance;
                next_state.balance_blinding = next_blinding_hex;
                next_state.current_commitment_x = server_resp.next_commitment.x;
                next_state.current_commitment_y = server_resp.next_commitment.y;
                next_state.current_anchor = server_resp.next_anchor;
                next_state.is_genesis = false;
                next_state.state_sig_epoch = Some(server_resp.next_state_sig_epoch);
                next_state.state_sig_root = Some(server_resp.next_state_sig_root);
                next_state.state_sig = Some(server_resp.next_state_sig.clone());

                next_state.save(&self.state_path)?;
                self.state = Some(next_state);
                PendingRequestJournal::clear(&self.journal_path)?;

                Ok(Some(server_resp))
            }
            "reserved" => {
                // 4. Server is still processing -- caller should retry later.
                Err(ClientError::ServerError(
                    "request still reserved on server, retry later".into(),
                ))
            }
            other => Err(ClientError::InvalidResponse(format!(
                "unexpected nullifier_status: {}",
                other
            ))),
        }
    }

    /// Return the pending journal entry, if one exists.
    pub fn get_pending_journal(&self) -> Result<Option<PendingRequestJournal>, ClientError> {
        PendingRequestJournal::read(&self.journal_path)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Request a clearance signature for mutual-close withdrawal.
    async fn request_clearance(
        &self,
        withdrawal_nullifier: &Felt252,
    ) -> Result<ClearanceResponse, ClientError> {
        let url = format!("{}/v1/withdraw/clearance", self.config.server_url);
        let req = ClearanceRequest {
            withdrawal_nullifier: *withdrawal_nullifier,
        };

        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let status_code = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        if !status_code.is_success() {
            return Err(ClientError::ServerError(format!(
                "clearance request failed: HTTP {} - {}",
                status_code, body
            )));
        }

        let clearance: ClearanceResponse =
            serde_json::from_str(&body).map_err(|e| ClientError::InvalidResponse(e.to_string()))?;
        if clearance.clear_sig_root.is_zero() {
            return Err(ClientError::InvalidResponse(
                "clearance response missing clear_sig_root".into(),
            ));
        }
        match lookup_clear_root(&self.config.trusted_epoch_roots, clearance.clear_sig_epoch) {
            Some(root) if root == clearance.clear_sig_root => {}
            Some(_) => {
                return Err(ClientError::VerificationFailed(
                    "clearance root does not match trusted epoch registry".into(),
                ));
            }
            None => {
                return Err(ClientError::VerificationFailed(
                    "clearance epoch is not trusted".into(),
                ));
            }
        }
        if clearance.clear_sig.epoch != clearance.clear_sig_epoch {
            return Err(ClientError::VerificationFailed(format!(
                "clearance signature epoch mismatch: {} != {}",
                clearance.clear_sig.epoch, clearance.clear_sig_epoch
            )));
        }
        let clear_msg = compute_clearance_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            withdrawal_nullifier,
        );
        if !XmssVerifier::verify(&clearance.clear_sig_root, &clear_msg, &clearance.clear_sig) {
            return Err(ClientError::VerificationFailed(
                "clearance XMSS verification failed".into(),
            ));
        }

        Ok(clearance)
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Sample a random nonzero `Felt252`.
fn sample_nonzero_felt(rng: &mut impl Rng) -> Felt252 {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        // Clear the top bits to stay below the Stark prime (~2^251).
        bytes[0] &= 0x07;
        let f = Felt252(bytes);
        if !f.is_zero() {
            return f;
        }
    }
}

/// Sample a random `FieldElement` suitable as a blinding factor.
fn sample_field_element(rng: &mut impl Rng) -> FieldElement {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    // Clear the top bits to stay below the Stark prime (~2^251).
    bytes[0] &= 0x07;
    FieldElement::from_bytes_be(&bytes)
}

/// Parse a 0x-prefixed hex blinding factor into a `FieldElement`.
fn parse_blinding(hex_str: &str) -> Result<FieldElement, ClientError> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let s = s.strip_prefix("0X").unwrap_or(s);
    let padded = format!("{:0>64}", s);
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&padded, &mut bytes)
        .map_err(|e| ClientError::Serialization(format!("bad blinding hex: {}", e)))?;
    Ok(FieldElement::from_bytes_be(&bytes))
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Convert a sibling vector from the indexer into the fixed-size array used
/// throughout the proof code.
fn siblings_from_vec(siblings: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH], ClientError> {
    siblings.try_into().map_err(|v: Vec<Felt252>| {
        ClientError::ProofGeneration(format!(
            "expected {} merkle siblings, got {}",
            MERKLE_DEPTH,
            v.len()
        ))
    })
}

fn proof_artifact_to_wire(artifact: ProofArtifact) -> ProofArtifactWire {
    ProofArtifactWire {
        backend: ProofBackendWire::StwoCairo,
        public_output_hash: artifact.public_output_hash,
        proof: base64::engine::general_purpose::STANDARD.encode(artifact.proof),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> String {
        let dir = std::env::temp_dir()
            .join("zkapi_client_test_wallet")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().to_string()
    }

    fn test_config(name: &str) -> ClientConfig {
        ClientConfig {
            protocol_version: 1,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdeadbeef),
            request_charge_cap: 100,
            policy_charge_cap: 50,
            policy_enabled: false,
            server_url: "http://localhost:9999".to_string(),
            state_dir: test_dir(name),
            trusted_epoch_roots: Vec::new(),
            proof_mode: test_proof_mode(),
        }
    }

    fn test_proof_mode() -> ClientProofMode {
        #[cfg(feature = "dev-witness-envelope")]
        {
            ClientProofMode::DevWitnessEnvelope
        }
        #[cfg(not(feature = "dev-witness-envelope"))]
        {
            let cairo_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../cairo")
                .canonicalize()
                .unwrap_or_else(|_| {
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../cairo")
                });
            ClientProofMode::StwoScarb {
                cairo_dir: cairo_dir.to_string_lossy().to_string(),
            }
        }
    }

    #[test]
    fn test_deposit_params_nonzero() {
        let config = test_config("deposit_params");
        let wallet = Wallet::new(config).unwrap();
        let (secret, commitment) = wallet.generate_deposit_params();
        assert!(!secret.is_zero());
        assert!(!commitment.is_zero());
    }

    #[test]
    fn test_confirm_deposit() {
        let config = test_config("confirm_deposit");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _commitment) = wallet.generate_deposit_params();

        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();
        let state = wallet.state().unwrap();
        assert!(state.is_genesis);
        assert_eq!(state.current_balance, 1000);
        assert_eq!(state.current_anchor, Felt252::ONE);
        assert!(state.state_sig.is_none());
    }

    #[test]
    fn test_deposit_rejects_duplicate() {
        let config = test_config("dup_deposit");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();

        let err = wallet
            .confirm_deposit(secret, 1, 500, 1700000000)
            .unwrap_err();
        assert!(matches!(err, ClientError::NoteAlreadyExists));
    }

    #[test]
    fn test_escape_hatch_withdrawal() {
        let config = test_config("escape");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();

        let dest = [
            0xdeu8, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let state = wallet.state().unwrap().clone();
        let commitment = compute_registration_commitment(&state.secret_s);
        let leaf = zkapi_core::leaf::compute_note_leaf(
            state.note_id,
            &commitment,
            state.deposit_amount,
            state.expiry_ts,
        );
        let mut tree = zkapi_core::merkle::MerkleTree::new();
        tree.insert(leaf);
        let root = tree.root();
        let siblings = tree.get_siblings(0).to_vec();

        let (inputs, proof) = wallet
            .withdrawal_escape_hatch(dest, root, siblings)
            .unwrap();

        assert_eq!(inputs.statement_type, STATEMENT_TYPE_WITHDRAWAL);
        assert!(!inputs.has_clearance);
        assert_eq!(inputs.final_balance, 1000);
        assert_eq!(inputs.destination, dest);
        assert_eq!(inputs.clear_sig_epoch, 0);
        assert_eq!(inputs.clear_sig_root, Felt252::ZERO);
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_wallet_persistence_across_instances() {
        let state_dir = test_dir("persist");
        {
            let config = ClientConfig {
                protocol_version: 1,
                chain_id: 1,
                contract_address: Felt252::from_u64(0xaa),
                request_charge_cap: 100,
                policy_charge_cap: 50,
                policy_enabled: false,
                server_url: "http://localhost:1".to_string(),
                state_dir: state_dir.clone(),
                trusted_epoch_roots: Vec::new(),
                proof_mode: test_proof_mode(),
            };
            let mut wallet = Wallet::new(config).unwrap();
            let (secret, _) = wallet.generate_deposit_params();
            wallet.confirm_deposit(secret, 7, 5000, 2000000000).unwrap();
        }
        // Create a new wallet instance against the same directory.
        {
            let config = ClientConfig {
                protocol_version: 1,
                chain_id: 1,
                contract_address: Felt252::from_u64(0xaa),
                request_charge_cap: 100,
                policy_charge_cap: 50,
                policy_enabled: false,
                server_url: "http://localhost:1".to_string(),
                state_dir,
                trusted_epoch_roots: Vec::new(),
                proof_mode: test_proof_mode(),
            };
            let wallet = Wallet::new(config).unwrap();
            let state = wallet.state().unwrap();
            assert_eq!(state.note_id, 7);
            assert_eq!(state.current_balance, 5000);
        }
    }

    #[test]
    fn test_archive_note() {
        let config = test_config("archive");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 3, 100, 0).unwrap();
        assert!(wallet.state().is_some());

        wallet.archive_note().unwrap();
        assert!(wallet.state().is_none());

        // The archive was written by the NoteState::archive method.
        // The test_dir recreates the directory, so the archive file
        // lives inside the wallet's state_dir.
    }

    #[test]
    fn test_sample_nonzero_felt() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let f = sample_nonzero_felt(&mut rng);
            assert!(!f.is_zero());
        }
    }

    #[test]
    fn test_parse_blinding_roundtrip() {
        let fe = FieldElement::from(42u64);
        let hex_str = format!("0x{}", hex::encode(fe.to_bytes_be()));
        let parsed = parse_blinding(&hex_str).unwrap();
        assert_eq!(fe, parsed);
    }

    #[test]
    fn test_base64_encode() {
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(engine.encode(b""), "");
        assert_eq!(engine.encode(b"f"), "Zg==");
        assert_eq!(engine.encode(b"fo"), "Zm8=");
        assert_eq!(engine.encode(b"foo"), "Zm9v");
        assert_eq!(engine.encode(b"foob"), "Zm9vYg==");
        assert_eq!(engine.encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(engine.encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_response_hash_mismatch_is_rejected() {
        let mut config = test_config("bad_response_hash");
        config.trusted_epoch_roots = vec![zkapi_types::EpochRoots {
            epoch: 1,
            state_root: Felt252::from_u64(0xabc),
            clear_root: Felt252::from_u64(0xdef),
        }];
        let mut wallet = Wallet::new(config).unwrap();
        let secret = Felt252::from_u64(55);
        wallet
            .confirm_deposit(secret, 0, 1000, 2_000_000_000)
            .unwrap();

        let blinding = FieldElement::ZERO;
        let anon = PedersenCommitment::commit(1000, &blinding);
        let mut response = trusted_shape_response(Felt252::from_u64(0xabc), "payload");
        response.response_hash = Felt252::from_u64(0xbad);

        let err = wallet
            .verify_request_response(&response, &anon, &FieldElement::ZERO, &blinding)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::VerificationFailed(msg) if msg.contains("response_hash"))
        );
    }

    #[test]
    fn test_unpublished_state_root_is_rejected_before_xmss_verify() {
        let config = test_config("unpublished_root");
        let mut wallet = Wallet::new(config).unwrap();
        let secret = Felt252::from_u64(56);
        wallet
            .confirm_deposit(secret, 0, 1000, 2_000_000_000)
            .unwrap();

        let blinding = FieldElement::ZERO;
        let anon = PedersenCommitment::commit(1000, &blinding);
        let response = trusted_shape_response(Felt252::from_u64(0xabc), "payload");

        let err = wallet
            .verify_request_response(&response, &anon, &FieldElement::ZERO, &blinding)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::VerificationFailed(msg) if msg.contains("epoch is not trusted"))
        );
    }

    fn trusted_shape_response(state_root: Felt252, payload: &str) -> RequestResponse {
        let blind_delta = Felt252::from_u64(7);
        let anon = PedersenCommitment::commit(1000, &FieldElement::ZERO);
        let updated =
            PedersenCommitment::server_update(&anon.point, 1, &felt_to_field(&blind_delta));
        let (x, y) = updated.to_affine();

        RequestResponse {
            status: "ok".to_string(),
            client_request_id: "test-request".to_string(),
            request_nullifier: Felt252::from_u64(1),
            response_code: 200,
            response_payload: payload.to_string(),
            response_hash: canonical_response_hash(payload.as_bytes()),
            charge_applied: 1,
            next_commitment: zkapi_types::wire::CurvePointWire {
                x: field_to_felt(&x),
                y: field_to_felt(&y),
            },
            next_anchor: Felt252::from_u64(9),
            blind_delta_srv: blind_delta,
            next_state_sig_epoch: 1,
            next_state_sig_root: state_root,
            next_state_sig: zkapi_types::XmssSignature {
                epoch: 1,
                leaf_index: 0,
                wots_sig: vec![Felt252::ZERO; zkapi_types::WOTS_LEN],
                auth_path: vec![Felt252::ZERO; zkapi_types::XMSS_TREE_HEIGHT],
            },
            policy_reason_code: None,
            policy_evidence_hash: None,
        }
    }

    #[test]
    fn test_no_pending_request_initially() {
        let config = test_config("no_pending");
        let wallet = Wallet::new(config).unwrap();
        assert!(!wallet.has_pending_request());
        assert!(wallet.get_pending_journal().unwrap().is_none());
    }
}
