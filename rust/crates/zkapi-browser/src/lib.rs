//! Browser-safe zkAPI v2 wallet operations.
//!
//! This crate deliberately owns neither storage nor transport. Every operation
//! accepts an immutable state snapshot and returns the complete next snapshot,
//! allowing the JavaScript host to commit state and its write-ahead journal in
//! one IndexedDB transaction before any network request is made.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zkapi_core::merkle::MerkleTree;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, RequestProver, RequestWitnessData, WithdrawalProver, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceResponseV2, CurvePointWire, Groth16ProofWire, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, SchnorrSignature, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserWalletConfig {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub request_charge_cap: u128,
    pub policy_charge_cap: u128,
    pub policy_enabled: bool,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteState {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequestJournal {
    pub exists: bool,
    pub client_request_id: String,
    pub nullifier: Felt252,
    pub payload_hash: Felt252,
    pub user_rerandomization: Felt252,
    pub created_at_ms: u64,
    pub prepared_request: ApiRequestV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositParams {
    pub secret: Felt252,
    pub registration_commitment: Felt252,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmDepositArgs {
    pub secret: Felt252,
    pub note_id: u32,
    pub amount: u128,
    pub expiry_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareRequestArgs {
    pub payload: String,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    pub client_request_id: String,
    pub request_time: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRequest {
    pub request: ApiRequestV2,
    pub journal: PendingRequestJournal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteResponseArgs {
    pub state: BrowserNoteState,
    pub journal: PendingRequestJournal,
    pub response: RequestResponseV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareWithdrawalArgs {
    pub mode: String,
    pub destination: String,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    #[serde(default)]
    pub clearance: Option<ClearanceResponseV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalPlan {
    pub mode: String,
    pub public_inputs: WithdrawalPublicInputsV2,
    pub siblings: Vec<Felt252>,
    pub proof: Groth16ProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteStatus {
    pub note_id: u32,
    pub deposit_amount: u128,
    pub current_balance: u128,
    pub expiry_ts: u64,
    pub is_genesis: bool,
    pub current_anchor: Felt252,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserWalletStatus {
    pub has_note: bool,
    pub pending_request: bool,
    pub note: Option<BrowserNoteStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub root: Felt252,
    pub next_note_id: u32,
    pub leaves: Vec<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTreePath {
    pub active_root: Felt252,
    pub note_id: u32,
    pub siblings: Vec<Felt252>,
}

/// Derive a path from the indexer's privacy-safe whole-tree snapshot and
/// verify the advertised root before any proof uses it.
pub fn tree_path(
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
) -> Result<BrowserTreePath> {
    if snapshot.leaves.len() != snapshot.next_note_id as usize {
        bail!("tree snapshot leaf count does not match next_note_id");
    }
    if (require_existing && note_id >= snapshot.next_note_id)
        || (!require_existing && note_id != snapshot.next_note_id)
    {
        bail!("requested note index is inconsistent with the tree snapshot");
    }
    let mut tree = MerkleTree::new();
    for (index, leaf) in snapshot.leaves.into_iter().enumerate() {
        tree.set_leaf(index as u32, leaf);
    }
    if tree.root() != snapshot.root {
        bail!("tree snapshot root verification failed");
    }
    Ok(BrowserTreePath {
        active_root: snapshot.root,
        note_id,
        siblings: tree.get_siblings(note_id).to_vec(),
    })
}

pub fn generate_deposit_params() -> DepositParams {
    loop {
        let secret = random_field();
        if !secret.is_zero() {
            return DepositParams {
                registration_commitment: core::registration_commitment(&secret),
                secret,
            };
        }
    }
}

pub fn confirm_deposit(
    config: &BrowserWalletConfig,
    args: ConfirmDepositArgs,
) -> Result<BrowserNoteState> {
    validate_state_identity(config, args.secret, args.amount)?;
    let blinding = random_scalar();
    let commitment = balance_commitment(args.amount, &blinding);
    Ok(BrowserNoteState {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        note_id: args.note_id,
        secret_s: args.secret,
        deposit_amount: args.amount,
        expiry_ts: args.expiry_ts,
        current_balance: args.amount,
        balance_blinding: blinding.to_hex(),
        current_commitment_x: commitment.x,
        current_commitment_y: commitment.y,
        current_anchor: Felt252::ONE,
        is_genesis: true,
        state_signature: None,
    })
}

pub fn wallet_status(
    state: Option<&BrowserNoteState>,
    journal: Option<&PendingRequestJournal>,
) -> BrowserWalletStatus {
    BrowserWalletStatus {
        has_note: state.is_some(),
        pending_request: journal.is_some_and(|entry| entry.exists),
        note: state.map(|state| BrowserNoteStatus {
            note_id: state.note_id,
            deposit_amount: state.deposit_amount,
            current_balance: state.current_balance,
            expiry_ts: state.expiry_ts,
            is_genesis: state.is_genesis,
            current_anchor: state.current_anchor,
            current_commitment_x: state.current_commitment_x,
            current_commitment_y: state.current_commitment_y,
        }),
    }
}

pub fn prepare_request(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    proving_key: &[u8],
) -> Result<PreparedRequest> {
    let prover = RequestProver::from_bytes(proving_key)?;
    prepare_request_with_prover(config, state, args, &prover)
}

pub fn prepare_request_with_prover(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    prover: &RequestProver,
) -> Result<PreparedRequest> {
    validate_state(config, state)?;
    if args.client_request_id.trim().is_empty() {
        bail!("client_request_id is required");
    }
    let siblings = siblings_array(args.merkle_siblings)?;
    let payload_hash = canonical_payload_hash(args.payload.as_bytes());
    let solvency_bound = if config.policy_enabled {
        config.policy_charge_cap
    } else {
        config.request_charge_cap
    };
    if state.current_balance < solvency_bound {
        bail!(
            "insufficient balance: need {solvency_bound}, have {}",
            state.current_balance
        );
    }
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = balance_commitment(state.current_balance, &current_blinding);
    ensure_stored_commitment(state, &current)?;
    let rerandomization = random_scalar();
    let anonymous = rerandomize(&current, &rerandomization)?;
    let nullifier = core::nullifier(&state.secret_s, &state.current_anchor);
    let request_context = canonical_request_context(&args.client_request_id, &payload_hash);
    let public_inputs = RequestPublicInputsV2 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id,
        contract_address: state.contract_address,
        active_root: args.active_root,
        state_signing_key_x: config.state_signing_key.x,
        state_signing_key_y: config.state_signing_key.y,
        request_time: args.request_time,
        solvency_bound,
        request_nullifier: nullifier,
        authorization_tag: core::authorization_tag(&nullifier, &request_context),
        anonymous_commitment_x: anonymous.x,
        anonymous_commitment_y: anonymous.y,
    };
    let proof = prover
        .prove(
            &public_inputs,
            RequestWitnessData {
                secret: state.secret_s,
                request_context,
                note_id: state.note_id,
                deposit_amount: state.deposit_amount,
                expiry: state.expiry_ts,
                merkle_siblings: siblings,
                current_balance: state.current_balance,
                current_blinding,
                rerandomization,
                current_anchor: state.current_anchor,
                is_genesis: state.is_genesis,
                state_signature: state.state_signature,
            },
        )
        .context("generate request proof")?;
    let request = ApiRequestV2 {
        client_request_id: args.client_request_id.clone(),
        payload: args.payload,
        payload_hash,
        public_inputs,
        proof,
    };
    let journal = PendingRequestJournal {
        exists: true,
        client_request_id: args.client_request_id,
        nullifier,
        payload_hash,
        user_rerandomization: rerandomization,
        created_at_ms: args.created_at_ms,
        prepared_request: request.clone(),
    };
    Ok(PreparedRequest { request, journal })
}

pub fn complete_response(
    config: &BrowserWalletConfig,
    args: CompleteResponseArgs,
) -> Result<BrowserNoteState> {
    validate_state(config, &args.state)?;
    let response = args.response;
    let journal = args.journal;
    if !journal.exists
        || response.client_request_id != journal.client_request_id
        || response.request_nullifier != journal.nullifier
    {
        bail!("response request identity mismatch");
    }
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        bail!("response payload hash mismatch");
    }
    // The browser may deliberately prove a higher, coarse-grained lease
    // budget than the deployment's minimum per-request cap. Bind settlement
    // to that exact public proof input rather than the static minimum.
    let cap = journal.prepared_request.public_inputs.solvency_bound;
    if response.charge_applied > cap || response.next_anchor.is_zero() {
        bail!("invalid charge or next anchor");
    }
    let current_blinding = parse_scalar(&args.state.balance_blinding)?;
    let current = balance_commitment(args.state.current_balance, &current_blinding);
    ensure_stored_commitment(&args.state, &current)?;
    let anonymous = rerandomize(&current, &journal.user_rerandomization)?;
    let expected = server_update(
        &anonymous,
        response.charge_applied,
        &response.blind_delta_srv,
    )?;
    if expected != response.next_commitment {
        bail!("next commitment algebra mismatch");
    }
    let message = core::state_message(
        args.state.protocol_version,
        args.state.chain_id,
        &args.state.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    if !verify_signature(
        &config.state_signing_key,
        &message,
        &response.next_state_signature,
    )? {
        bail!("invalid next-state signature");
    }
    let next_blinding = add_blindings(
        &add_blindings(&current_blinding, &journal.user_rerandomization),
        &response.blind_delta_srv,
    );
    let mut next = args.state;
    next.current_balance = next
        .current_balance
        .checked_sub(response.charge_applied)
        .ok_or_else(|| anyhow!("charge exceeds balance"))?;
    next.balance_blinding = next_blinding.to_hex();
    next.current_commitment_x = response.next_commitment.x;
    next.current_commitment_y = response.next_commitment.y;
    next.current_anchor = response.next_anchor;
    next.is_genesis = false;
    next.state_signature = Some(response.next_state_signature);
    Ok(next)
}

pub fn withdrawal_nullifier(state: &BrowserNoteState) -> Felt252 {
    core::nullifier(&state.secret_s, &state.current_anchor)
}

pub fn prepare_withdrawal(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareWithdrawalArgs,
    proving_key: &[u8],
) -> Result<WithdrawalPlan> {
    validate_state(config, state)?;
    let has_clearance = match args.mode.as_str() {
        "mutual" => true,
        "escape" => false,
        _ => bail!("withdrawal mode must be mutual or escape"),
    };
    let destination = parse_address(&args.destination)?;
    let siblings = siblings_array(args.merkle_siblings.clone())?;
    let nullifier = withdrawal_nullifier(state);
    let clearance_signature = if has_clearance {
        let clearance = args
            .clearance
            .as_ref()
            .ok_or_else(|| anyhow!("mutual withdrawal requires server clearance"))?;
        if clearance.withdrawal_nullifier != nullifier {
            bail!("clearance nullifier mismatch");
        }
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        if !verify_signature(
            &config.clearance_signing_key,
            &message,
            &clearance.signature,
        )? {
            bail!("invalid clearance signature");
        }
        Some(clearance.signature)
    } else {
        if args.clearance.is_some() {
            bail!("escape withdrawal must not include clearance");
        }
        None
    };
    let mut destination_bytes = [0u8; 32];
    destination_bytes[12..].copy_from_slice(&destination);
    let destination_field = Felt252(destination_bytes);
    let public_inputs = WithdrawalPublicInputsV2 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id,
        contract_address: state.contract_address,
        active_root: args.active_root,
        state_signing_key_x: config.state_signing_key.x,
        state_signing_key_y: config.state_signing_key.y,
        clearance_signing_key_x: config.clearance_signing_key.x,
        clearance_signing_key_y: config.clearance_signing_key.y,
        note_id: state.note_id,
        final_balance: state.current_balance,
        destination,
        withdrawal_nullifier: nullifier,
        has_clearance,
        withdrawal_tag: core::withdrawal_tag(
            &nullifier,
            &destination_field,
            state.current_balance,
            has_clearance,
        ),
    };
    let proof = WithdrawalProver::from_bytes(proving_key)?
        .prove(
            &public_inputs,
            WithdrawalWitnessData {
                secret: state.secret_s,
                deposit_amount: state.deposit_amount,
                expiry: state.expiry_ts,
                merkle_siblings: siblings,
                final_blinding: parse_scalar(&state.balance_blinding)?,
                current_anchor: state.current_anchor,
                is_genesis: state.is_genesis,
                state_signature: state.state_signature,
                clearance_signature,
            },
        )
        .context("generate withdrawal proof")?;
    Ok(WithdrawalPlan {
        mode: args.mode,
        public_inputs,
        siblings: args.merkle_siblings,
        proof,
    })
}

fn validate_state_identity(
    config: &BrowserWalletConfig,
    secret: Felt252,
    amount: u128,
) -> Result<()> {
    if config.protocol_version != 2 {
        bail!("unsupported protocol version {}", config.protocol_version);
    }
    if config.contract_address.is_zero() || secret.is_zero() || amount == 0 {
        bail!("deposit identity contains a zero value");
    }
    Ok(())
}

fn validate_state(config: &BrowserWalletConfig, state: &BrowserNoteState) -> Result<()> {
    if state.protocol_version != config.protocol_version
        || state.chain_id != config.chain_id
        || state.contract_address != config.contract_address
    {
        bail!("wallet state belongs to a different zkAPI deployment");
    }
    validate_state_identity(config, state.secret_s, state.deposit_amount)
}

fn ensure_stored_commitment(state: &BrowserNoteState, commitment: &CurvePointWire) -> Result<()> {
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        bail!("persisted balance commitment is inconsistent");
    }
    Ok(())
}

fn parse_scalar(value: &str) -> Result<Felt252> {
    Felt252::from_hex(value).map_err(|error| anyhow!("invalid balance blinding: {error}"))
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH]> {
    let count = values.len();
    values
        .try_into()
        .map_err(|_| anyhow!("expected {MERKLE_DEPTH} Merkle siblings, got {count}"))
}

fn parse_address(value: &str) -> Result<[u8; 20]> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 40 {
        bail!("destination must be a 20-byte hex address");
    }
    let mut address = [0u8; 20];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        address[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).context("address is not UTF-8")?,
            16,
        )
        .context("address contains non-hex characters")?;
    }
    Ok(address)
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    fn encode<T: Serialize>(value: &T) -> std::result::Result<String, JsValue> {
        serde_json::to_string(value).map_err(js_error)
    }

    fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> std::result::Result<T, JsValue> {
        serde_json::from_str(value).map_err(js_error)
    }

    fn js_error(error: impl std::fmt::Display) -> JsValue {
        JsValue::from_str(&error.to_string())
    }

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    #[wasm_bindgen]
    pub fn browser_generate_deposit() -> std::result::Result<String, JsValue> {
        encode(&generate_deposit_params())
    }

    #[wasm_bindgen]
    pub fn browser_confirm_deposit(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&confirm_deposit(&decode(config_json)?, decode(args_json)?).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_wallet_status(
        state_json: Option<String>,
        journal_json: Option<String>,
    ) -> std::result::Result<String, JsValue> {
        let state = state_json.as_deref().map(decode).transpose()?;
        let journal = journal_json.as_deref().map(decode).transpose()?;
        encode(&wallet_status(state.as_ref(), journal.as_ref()))
    }

    #[wasm_bindgen]
    pub fn browser_prepare_request(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_request(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_error)?,
        )
    }

    #[wasm_bindgen]
    pub struct BrowserRequestProver {
        prover: RequestProver,
    }

    #[wasm_bindgen]
    impl BrowserRequestProver {
        #[wasm_bindgen(constructor)]
        pub fn new(proving_key: &[u8]) -> std::result::Result<BrowserRequestProver, JsValue> {
            Ok(Self {
                prover: RequestProver::from_bytes(proving_key).map_err(js_error)?,
            })
        }

        pub fn prepare_request(
            &self,
            config_json: &str,
            state_json: &str,
            args_json: &str,
        ) -> std::result::Result<String, JsValue> {
            encode(
                &prepare_request_with_prover(
                    &decode(config_json)?,
                    &decode(state_json)?,
                    decode(args_json)?,
                    &self.prover,
                )
                .map_err(js_error)?,
            )
        }
    }

    #[wasm_bindgen]
    pub fn browser_complete_response(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&complete_response(&decode(config_json)?, decode(args_json)?).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_withdrawal_nullifier(state_json: &str) -> std::result::Result<String, JsValue> {
        encode(&withdrawal_nullifier(&decode(state_json)?))
    }

    #[wasm_bindgen]
    pub fn browser_tree_path(
        snapshot_json: &str,
        note_id: u32,
        require_existing: bool,
    ) -> std::result::Result<String, JsValue> {
        encode(&tree_path(decode(snapshot_json)?, note_id, require_existing).map_err(js_error)?)
    }

    #[wasm_bindgen]
    pub fn browser_prepare_withdrawal(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_withdrawal(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_error)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zkapi_proof::compact::{RequestVerifier, WithdrawalVerifier};

    fn config() -> BrowserWalletConfig {
        BrowserWalletConfig {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: Felt252::from_u64(99),
            request_charge_cap: 100,
            policy_charge_cap: 200,
            policy_enabled: false,
            state_signing_key: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ONE,
            },
            clearance_signing_key: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ONE,
            },
        }
    }

    #[test]
    fn deposit_state_roundtrip_has_consistent_commitment() {
        let config = config();
        let params = generate_deposit_params();
        let state = confirm_deposit(
            &config,
            ConfirmDepositArgs {
                secret: params.secret,
                note_id: 7,
                amount: 2_000_000,
                expiry_ts: 1_900_000_000,
            },
        )
        .unwrap();
        let blinding = parse_scalar(&state.balance_blinding).unwrap();
        let commitment = balance_commitment(state.current_balance, &blinding);
        ensure_stored_commitment(&state, &commitment).unwrap();
        assert_eq!(wallet_status(Some(&state), None).note.unwrap().note_id, 7);
    }

    #[test]
    fn deployment_mismatch_is_rejected() {
        let mut wrong = config();
        wrong.chain_id = 1;
        let params = generate_deposit_params();
        let state = confirm_deposit(
            &config(),
            ConfirmDepositArgs {
                secret: params.secret,
                note_id: 0,
                amount: 1,
                expiry_ts: 1,
            },
        )
        .unwrap();
        assert!(validate_state(&wrong, &state).is_err());
    }

    #[test]
    fn address_parser_is_strict() {
        assert_eq!(
            parse_address("0x1111111111111111111111111111111111111111").unwrap(),
            [0x11; 20]
        );
        assert!(parse_address("0x1234").is_err());
        assert!(parse_address("0xgg11111111111111111111111111111111111111").is_err());
    }

    #[test]
    fn fetched_key_bytes_produce_verifiable_browser_proofs() {
        let config = config();
        let params = generate_deposit_params();
        let note_id = 0;
        let amount = 2_000_000;
        let expiry = 1_900_000_000;
        let state = confirm_deposit(
            &config,
            ConfirmDepositArgs {
                secret: params.secret,
                note_id,
                amount,
                expiry_ts: expiry,
            },
        )
        .unwrap();
        let leaf = core::note_leaf(note_id, &params.registration_commitment, amount, expiry);
        let mut tree = MerkleTree::new();
        tree.set_leaf(note_id, leaf);
        let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2");

        let request_key = std::fs::read(setup.join("request.pk")).unwrap();
        let request_prover = RequestProver::from_bytes(&request_key).unwrap();
        let prepared = prepare_request_with_prover(
            &config,
            &state,
            PrepareRequestArgs {
                payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".into(),
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(note_id).to_vec(),
                client_request_id: "browser-proof-test".into(),
                request_time: 1_800_000_000,
                created_at_ms: 1_800_000_000_000,
            },
            &request_prover,
        )
        .unwrap();
        assert!(RequestVerifier::load(&setup)
            .unwrap()
            .verify(&prepared.request.public_inputs, &prepared.request.proof)
            .unwrap());

        let withdrawal_key = std::fs::read(setup.join("withdrawal.pk")).unwrap();
        let plan = prepare_withdrawal(
            &config,
            &state,
            PrepareWithdrawalArgs {
                mode: "escape".into(),
                destination: "0x1111111111111111111111111111111111111111".into(),
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(note_id).to_vec(),
                clearance: None,
            },
            &withdrawal_key,
        )
        .unwrap();
        assert!(WithdrawalVerifier::load(&setup)
            .unwrap()
            .verify(&plan.public_inputs, &plan.proof)
            .unwrap());
    }
}
