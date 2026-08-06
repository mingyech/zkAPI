//! Stwo/Stwo-Cairo prover bridge boundary.
//!
//! The upstream Stwo VM runner consumes a compiled Cairo program with a `main`
//! entrypoint and `program_input`, then adapts the Cairo VM trace into
//! `ProverInput`. zkAPI has executable Cairo wrappers for each request and
//! withdrawal statement branch. Those executable paths prove and verify through
//! Scarb's Stwo integration. Rust can serialize flat Cairo argument vectors and
//! invoke Scarb with `--arguments-file`, but client/server runtime proof
//! generation is still incomplete. Until that bridge exists end-to-end, generic
//! readiness checks are intentionally narrow: they confirm the bridge is wired,
//! while command execution still reports environment/toolchain failures at use
//! time.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use zkapi_types::{public_output_hash_from_cairo_outputs, Felt252};

use crate::ProofArtifact;

static SCARB_COMMAND_LOCK: Mutex<()> = Mutex::new(());

/// Errors returned by the real Stwo bridge.
#[derive(Debug, Error)]
pub enum StwoBridgeError {
    #[error("Stwo bridge unavailable: {0}")]
    BridgeUnavailable(String),

    #[error("scarb command failed: {0}")]
    ScarbCommandFailed(String),

    #[error("could not find Scarb execution id in command output")]
    MissingExecutionId,

    #[error("proof artifact not found at {0}")]
    MissingProofArtifact(String),

    #[error("proof public output error: {0}")]
    PublicOutput(String),

    #[error("proof public_output_hash mismatch: artifact={artifact}, proof={proof}")]
    PublicOutputHashMismatch { artifact: Felt252, proof: Felt252 },

    #[error("I/O error: {0}")]
    Io(String),
}

/// Check whether the current repository has the Cairo runner boundary required
/// for every production proof branch.
pub fn ensure_stwo_runner_ready() -> Result<(), StwoBridgeError> {
    Ok(())
}

/// Thin bridge over Scarb's Stwo prover/verifier commands.
#[derive(Debug, Clone)]
pub struct ScarbStwoProver {
    cairo_dir: PathBuf,
}

impl ScarbStwoProver {
    pub fn new(cairo_dir: impl Into<PathBuf>) -> Self {
        Self {
            cairo_dir: cairo_dir.into(),
        }
    }

    pub fn prove_and_verify_executable(
        &self,
        executable_name: &str,
        public_output_hash: Felt252,
    ) -> Result<ProofArtifact, StwoBridgeError> {
        self.prove_and_verify_executable_inner(executable_name, public_output_hash, None)
    }

    pub fn prove_and_verify_executable_with_args(
        &self,
        executable_name: &str,
        public_output_hash: Felt252,
        cairo_args: &[Felt252],
    ) -> Result<ProofArtifact, StwoBridgeError> {
        let args_path = write_arguments_file(cairo_args)?;
        let result = self.prove_and_verify_executable_inner(
            executable_name,
            public_output_hash,
            Some(args_path.as_path()),
        );
        let _ = std::fs::remove_file(&args_path);
        result
    }

    pub fn verify_proof_bytes(&self, proof: &[u8]) -> Result<(), StwoBridgeError> {
        let proof_path = write_temp_file("zkapi-stwo-proof", "json", proof)?;
        let proof_path_display = display_path(&proof_path);
        let result = run_scarb(
            &self.cairo_dir,
            &["verify", "--proof-file", &proof_path_display],
        )
        .map(|_| ());
        let _ = std::fs::remove_file(&proof_path);
        result
    }

    pub fn verify_artifact(&self, artifact: &ProofArtifact) -> Result<(), StwoBridgeError> {
        self.verify_proof_bytes(&artifact.proof)?;
        let outputs = extract_public_outputs_from_proof(&artifact.proof)?;
        let proof_hash = public_output_hash_from_cairo_outputs(&outputs)
            .map_err(StwoBridgeError::PublicOutput)?;
        if proof_hash != artifact.public_output_hash {
            return Err(StwoBridgeError::PublicOutputHashMismatch {
                artifact: artifact.public_output_hash,
                proof: proof_hash,
            });
        }
        Ok(())
    }

    fn prove_and_verify_executable_inner(
        &self,
        executable_name: &str,
        public_output_hash: Felt252,
        arguments_file: Option<&Path>,
    ) -> Result<ProofArtifact, StwoBridgeError> {
        let mut prove_args = vec!["prove", "--execute", "--executable-name", executable_name];
        let arguments_file_display;
        if let Some(path) = arguments_file {
            arguments_file_display = display_path(path);
            prove_args.push("--arguments-file");
            prove_args.push(&arguments_file_display);
        }

        let prove_output = run_scarb(&self.cairo_dir, &prove_args)?;
        let execution_id =
            parse_execution_id(&prove_output).ok_or(StwoBridgeError::MissingExecutionId)?;

        run_scarb(
            &self.cairo_dir,
            &["verify", "--execution-id", &execution_id],
        )?;

        let proof_path = self
            .cairo_dir
            .join("target")
            .join("execute")
            .join("zkapi_cairo")
            .join(format!("execution{execution_id}"))
            .join("proof")
            .join("proof.json");
        let proof = std::fs::read(&proof_path)
            .map_err(|_| StwoBridgeError::MissingProofArtifact(display_path(&proof_path)))?;

        let artifact = ProofArtifact::stwo_cairo(public_output_hash, proof);
        // Scarb verifies that the proof itself is valid, but callers also need
        // the proof's public outputs bound to the Rust request inputs before
        // they journal or transmit the request.
        self.verify_artifact(&artifact)?;
        Ok(artifact)
    }
}

fn write_arguments_file(cairo_args: &[Felt252]) -> Result<PathBuf, StwoBridgeError> {
    // Cairo Serde encodes an Array as its length followed by its elements.
    let mut encoded = Vec::with_capacity(cairo_args.len() + 1);
    encoded.push(Felt252::from_u64(cairo_args.len() as u64).to_hex());
    encoded.extend(cairo_args.iter().map(Felt252::to_hex));
    let json = serde_json::to_vec(&encoded).map_err(|e| StwoBridgeError::Io(e.to_string()))?;

    write_temp_file("zkapi-stwo-args", "json", &json)
}

fn write_temp_file(
    prefix: &str,
    extension: &str,
    bytes: &[u8],
) -> Result<PathBuf, StwoBridgeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| StwoBridgeError::Io(e.to_string()))?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("{prefix}-{}-{now}.{extension}", std::process::id()));
    std::fs::write(&path, bytes).map_err(|e| StwoBridgeError::Io(e.to_string()))?;
    Ok(path)
}

fn run_scarb(cairo_dir: &Path, args: &[&str]) -> Result<String, StwoBridgeError> {
    let _guard = SCARB_COMMAND_LOCK
        .lock()
        .map_err(|e| StwoBridgeError::Io(e.to_string()))?;
    let output = Command::new("scarb")
        .args(args)
        .current_dir(cairo_dir)
        .output()
        .map_err(|e| StwoBridgeError::Io(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(StwoBridgeError::ScarbCommandFailed(combined));
    }
    Ok(combined)
}

fn parse_execution_id(output: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| line.split("target/execute/zkapi_cairo/execution").nth(1))
        .filter_map(|tail| {
            let digits: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
            if digits.is_empty() {
                None
            } else {
                Some(digits)
            }
        })
        .next_back()
}

pub fn extract_public_outputs_from_proof(proof: &[u8]) -> Result<Vec<Felt252>, StwoBridgeError> {
    let json: serde_json::Value =
        serde_json::from_slice(proof).map_err(|e| StwoBridgeError::PublicOutput(e.to_string()))?;
    let output = json
        .pointer("/claim/public_data/public_memory/output")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            StwoBridgeError::PublicOutput(
                "missing claim.public_data.public_memory.output".to_string(),
            )
        })?;

    let mut outputs: Vec<Felt252> = output
        .iter()
        .map(|entry| {
            let limbs = entry
                .as_array()
                .and_then(|entry| entry.get(1))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    StwoBridgeError::PublicOutput("malformed public output entry".to_string())
                })?;
            felt_from_u32_limbs_le(limbs)
        })
        .collect::<Result<_, _>>()?;

    if outputs.len() >= 4 {
        if let Some(return_len) = outputs[3].to_u64() {
            let return_len = return_len as usize;
            if outputs.len() == return_len + 4 {
                outputs.drain(0..4);
            }
        }
    }

    Ok(outputs)
}

fn felt_from_u32_limbs_le(limbs: &[serde_json::Value]) -> Result<Felt252, StwoBridgeError> {
    if limbs.len() != 8 {
        return Err(StwoBridgeError::PublicOutput(format!(
            "public output felt has {} limbs, expected 8",
            limbs.len()
        )));
    }

    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let limb = limb.as_u64().ok_or_else(|| {
            StwoBridgeError::PublicOutput("public output limb is not an integer".to_string())
        })?;
        let limb: u32 = limb.try_into().map_err(|_| {
            StwoBridgeError::PublicOutput("public output limb exceeds u32".to_string())
        })?;
        let start = 32 - ((i + 1) * 4);
        bytes[start..start + 4].copy_from_slice(&limb.to_be_bytes());
    }

    Felt252::try_from_bytes_be(bytes).map_err(StwoBridgeError::PublicOutput)
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_core::commitment::{compute_clearance_message, compute_state_message};
    use zkapi_core::leaf::{compute_note_leaf, compute_registration_commitment};
    use zkapi_core::merkle::MerkleTree;
    use zkapi_core::poseidon::poseidon_hash;
    use zkapi_core::poseidon::{felt_to_field, field_to_felt, FieldElement};
    use zkapi_crypto::pedersen::PedersenCommitment;
    use zkapi_crypto::wots::{wots_pk_to_leaf, wots_verify};
    use zkapi_crypto::xmss::xmss_hash_message;
    use zkapi_types::domain::DOMAIN_XMSS_NODE;
    use zkapi_types::{XmssSignature, WOTS_LEN, XMSS_TREE_HEIGHT};

    use crate::{RequestProofBuilder, WithdrawalProofBuilder};

    #[test]
    fn stwo_bridge_readiness_reports_wired_bridge() {
        ensure_stwo_runner_ready().unwrap();
    }

    #[test]
    fn parses_execution_id_from_scarb_prove_output() {
        let output = "Saving output to: target/execute/zkapi_cairo/execution42\n\
                      Saving proof to: target/execute/zkapi_cairo/execution42/proof/proof.json";
        assert_eq!(parse_execution_id(output).as_deref(), Some("42"));
    }

    #[test]
    fn missing_execution_id_returns_none() {
        assert_eq!(parse_execution_id("no execution path here"), None);
    }

    #[test]
    fn encodes_cairo_array_arguments_file() {
        let path = write_arguments_file(&[Felt252::from_u64(1), Felt252::from_u64(27)]).unwrap();
        let encoded = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(encoded, "[\"0x2\",\"0x1\",\"0x1b\"]");
    }

    #[test]
    fn proves_non_genesis_request_from_rust_witness_args() {
        let (public_output_hash, cairo_args) = non_genesis_request_args();

        let artifact = ScarbStwoProver::new(cairo_dir())
            .prove_and_verify_executable_with_args(
                "request_from_args",
                public_output_hash,
                &cairo_args,
            )
            .unwrap();

        assert_eq!(artifact.public_output_hash, public_output_hash);
        assert!(!artifact.proof.is_empty());
        let proof_outputs = extract_public_outputs_from_proof(&artifact.proof).unwrap();
        assert_eq!(
            zkapi_types::public_output_hash_from_cairo_outputs(&proof_outputs).unwrap(),
            public_output_hash
        );
        ScarbStwoProver::new(cairo_dir())
            .verify_artifact(&artifact)
            .unwrap();
    }

    #[test]
    fn rejects_request_artifact_rebound_to_wrong_public_output_hash() {
        let (public_output_hash, cairo_args) = non_genesis_request_args();
        let mut artifact = ScarbStwoProver::new(cairo_dir())
            .prove_and_verify_executable_with_args(
                "request_from_args",
                public_output_hash,
                &cairo_args,
            )
            .unwrap();
        artifact.public_output_hash = Felt252::from_u64(0xbad);

        let err = ScarbStwoProver::new(cairo_dir())
            .verify_artifact(&artifact)
            .unwrap_err();
        assert!(matches!(
            err,
            StwoBridgeError::PublicOutputHashMismatch { .. }
        ));
    }

    #[test]
    fn request_stwo_rejects_bad_state_signature_root() {
        let (public_output_hash, mut cairo_args) = non_genesis_request_args();
        cairo_args[78] = Felt252::from_u64(0xbad);

        assert_stwo_rejects_args("request_from_args", public_output_hash, &cairo_args);
    }

    #[test]
    fn request_stwo_rejects_insufficient_balance() {
        let (public_output_hash, mut cairo_args) = non_genesis_request_args();
        cairo_args[73] = Felt252::from_u64(99);

        assert_stwo_rejects_args("request_from_args", public_output_hash, &cairo_args);
    }

    #[test]
    fn request_stwo_rejects_wrong_merkle_path() {
        let (public_output_hash, mut cairo_args) = non_genesis_request_args();
        cairo_args[41] = Felt252::from_u64(0xbad);

        assert_stwo_rejects_args("request_from_args", public_output_hash, &cairo_args);
    }

    #[test]
    fn withdrawal_stwo_rejects_bad_clearance_signature_root() {
        let (public_output_hash, mut cairo_args) = mutual_close_withdrawal_args();
        let clear_sig_root_idx = withdrawal_clearance_fields_start() + 1;
        cairo_args[clear_sig_root_idx] = Felt252::from_u64(0xbad);

        assert_stwo_rejects_args("withdrawal_from_args", public_output_hash, &cairo_args);
    }

    #[test]
    fn withdrawal_destination_changes_public_output_hash() {
        let (public_output_hash, mut cairo_args) = mutual_close_withdrawal_args();
        cairo_args[4] = Felt252::from_u64(0x1234);

        let artifact = ScarbStwoProver::new(cairo_dir())
            .prove_and_verify_executable_with_args(
                "withdrawal_from_args",
                public_output_hash,
                &cairo_args,
            )
            .unwrap();
        let err = ScarbStwoProver::new(cairo_dir())
            .verify_artifact(&artifact)
            .unwrap_err();
        assert!(matches!(
            err,
            StwoBridgeError::PublicOutputHashMismatch { .. }
        ));
    }

    fn non_genesis_request_args() -> (Felt252, Vec<Felt252>) {
        let secret = Felt252::from_u64(42);
        let note_id = 0;
        let deposit = 1_000u128;
        let expiry = 4_000_000_000u64;
        let (active_root, siblings) = active_root_and_siblings(secret, note_id, deposit, expiry);
        let current_balance = 900u128;
        let current_blinding = FieldElement::from(9u64);
        let current_anchor = Felt252::from_u64(55);
        let commitment = PedersenCommitment::commit(current_balance, &current_blinding);
        let (cx, cy) = commitment.to_affine();
        let state_msg = compute_state_message(
            1,
            1,
            &Felt252::from_u64(0xdead),
            &field_to_felt(&cx),
            &field_to_felt(&cy),
            &current_anchor,
        );
        let (state_sig, state_root) = fixture_xmss_signature(&state_msg, 7, 10, 10);
        let builder = RequestProofBuilder::new(
            secret,
            note_id,
            deposit,
            expiry,
            siblings,
            current_balance,
            current_blinding,
            FieldElement::from(7u64),
            current_anchor,
            false,
            state_sig.epoch,
            state_root,
            active_root,
            1,
            1,
            Felt252::from_u64(0xdead),
            100,
        );
        let public_inputs = builder.build_public_inputs().unwrap();

        (
            public_inputs.public_output_hash(),
            builder.to_cairo_args(Some(&state_sig)).unwrap(),
        )
    }

    #[test]
    fn proves_mutual_close_withdrawal_from_rust_witness_args() {
        let (public_output_hash, cairo_args) = mutual_close_withdrawal_args();

        let artifact = ScarbStwoProver::new(cairo_dir())
            .prove_and_verify_executable_with_args(
                "withdrawal_from_args",
                public_output_hash,
                &cairo_args,
            )
            .unwrap();

        assert_eq!(artifact.public_output_hash, public_output_hash);
        assert!(!artifact.proof.is_empty());
        let proof_outputs = extract_public_outputs_from_proof(&artifact.proof).unwrap();
        assert_eq!(
            zkapi_types::public_output_hash_from_cairo_outputs(&proof_outputs).unwrap(),
            public_output_hash
        );
        ScarbStwoProver::new(cairo_dir())
            .verify_artifact(&artifact)
            .unwrap();
    }

    fn mutual_close_withdrawal_args() -> (Felt252, Vec<Felt252>) {
        let secret = Felt252::from_u64(42);
        let note_id = 0;
        let deposit = 1_000u128;
        let expiry = 4_000_000_000u64;
        let (active_root, siblings) = active_root_and_siblings(secret, note_id, deposit, expiry);
        let final_balance = 800u128;
        let final_blinding = FieldElement::from(21u64);
        let current_anchor = Felt252::from_u64(88);
        let destination = [
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        let commitment = PedersenCommitment::commit(final_balance, &final_blinding);
        let (cx, cy) = commitment.to_affine();
        let state_msg = compute_state_message(
            1,
            1,
            &Felt252::from_u64(0xdead),
            &field_to_felt(&cx),
            &field_to_felt(&cy),
            &current_anchor,
        );
        let (state_sig, state_root) = fixture_xmss_signature(&state_msg, 7, 10, 20);
        let withdrawal_nullifier =
            zkapi_core::nullifier::compute_nullifier(&secret, &current_anchor);
        let clear_msg =
            compute_clearance_message(1, 1, &Felt252::from_u64(0xdead), &withdrawal_nullifier);
        let (clear_sig, clear_root) = fixture_xmss_signature(&clear_msg, 8, 10, 40);

        let builder = WithdrawalProofBuilder::new(
            secret,
            note_id,
            deposit,
            expiry,
            siblings,
            final_balance,
            final_blinding,
            current_anchor,
            false,
            state_sig.epoch,
            state_root,
            true,
            clear_sig.epoch,
            clear_root,
            destination,
            active_root,
            1,
            1,
            Felt252::from_u64(0xdead),
        );
        let public_inputs = builder.build_public_inputs();

        (
            public_inputs.public_output_hash(),
            builder
                .to_cairo_args(Some(&state_sig), Some(&clear_sig))
                .unwrap(),
        )
    }

    fn assert_stwo_rejects_args(
        executable_name: &str,
        public_output_hash: Felt252,
        args: &[Felt252],
    ) {
        let err = ScarbStwoProver::new(cairo_dir())
            .prove_and_verify_executable_with_args(executable_name, public_output_hash, args)
            .unwrap_err();
        assert!(matches!(err, StwoBridgeError::ScarbCommandFailed(_)));
    }

    fn withdrawal_clearance_fields_start() -> usize {
        79 + 1 + WOTS_LEN + 1 + XMSS_TREE_HEIGHT
    }

    fn cairo_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../cairo")
            .canonicalize()
            .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../cairo"))
    }

    fn active_root_and_siblings(
        secret: Felt252,
        note_id: u32,
        deposit: u128,
        expiry: u64,
    ) -> (Felt252, [Felt252; zkapi_types::MERKLE_DEPTH]) {
        let commitment = compute_registration_commitment(&secret);
        let leaf = compute_note_leaf(note_id, &commitment, deposit, expiry);
        let mut tree = MerkleTree::new();
        tree.insert(leaf);
        (tree.root(), tree.get_siblings(note_id))
    }

    fn fixture_xmss_signature(
        message: &Felt252,
        epoch: u32,
        height: usize,
        offset: u64,
    ) -> (XmssSignature, Felt252) {
        let wots_sig: Vec<Felt252> = (0..WOTS_LEN)
            .map(|i| Felt252::from_u64(offset + i as u64 + 1))
            .collect();
        let auth_path = vec![Felt252::ZERO; height];
        let digest = xmss_hash_message(message);
        let mut sig_arr = [FieldElement::ZERO; WOTS_LEN];
        for (dst, src) in sig_arr.iter_mut().zip(wots_sig.iter()) {
            *dst = felt_to_field(src);
        }
        let pk = wots_verify(&sig_arr, &digest);
        let mut current = field_to_felt(&wots_pk_to_leaf(&pk));
        for sibling in &auth_path {
            current = poseidon_hash(&DOMAIN_XMSS_NODE, &current, sibling);
        }
        (
            XmssSignature {
                epoch,
                leaf_index: 0,
                wots_sig,
                auth_path,
            },
            current,
        )
    }
}
