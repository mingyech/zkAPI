# Stwo Prover Bridge

The production proof artifact boundary is `zkapi_proof::ProofArtifact`: opaque
proof bytes plus the canonical public-output hash. Private witness envelopes are
only available behind the `dev-witness-envelope` feature.

The runtime Stwo/Stwo-Cairo bridge is wired through Scarb. The Cairo package
exposes executable targets for every current request/withdrawal statement branch.
The upstream `stwo-vm-runner` expects a compiled Cairo program with entrypoint
`main` and optional `program_input`; it runs that program in proof mode, adapts
the VM trace into `ProverInput`, and then `stwo-cairo-prover` can create and
verify the proof artifact.

The Scarb installation must include the `scarb-execute`, `scarb-prove`, and
`scarb-verify` companion binaries. Check with `scarb commands`. If any are
missing, use the complete official Scarb release bundle; a core-only package
cannot run the production proof path.

Current executable-wrapper status:

- `request_genesis` builds, executes, proves with `scarb prove`, and verifies
  with `scarb verify`;
- `request_non_genesis` builds, executes, proves with `scarb prove`, and
  verifies with `scarb verify`;
- `withdrawal_genesis_escape` builds, executes, proves with `scarb prove`, and
  verifies with `scarb verify`;
- `withdrawal_non_genesis_escape` builds, executes, proves with `scarb prove`,
  and verifies with `scarb verify`;
- `withdrawal_mutual_close` builds, executes, proves with `scarb prove`, and
  verifies with `scarb verify`.
- `request_from_args` and `withdrawal_from_args` expose flat felt-array
  witness entrypoints for Rust-driven `--arguments-file` execution;
- `zkapi-client` produces opaque `ProofArtifactWire` values by invoking
  `ScarbStwoProver` in default mode;
- `zkapi-server` verifies `ProofArtifactWire` values by checking the canonical
  public-output hash, running `scarb verify --proof-file`, extracting the proof
  public outputs from `proof.json`, and requiring those outputs to hash back to
  the artifact's `public_output_hash`.

Remaining compatibility work:

- promote the flat felt-array witness format into a versioned runtime contract;
- replace the Scarb CLI subprocess bridge with direct `stwo-vm-runner` /
  `stwo-cairo-prover` integration if deployment needs lower latency;
- expand real-proof integration tests beyond executable fixtures to full
  request/recovery/challenge lifecycles.

Private witness envelopes remain available only behind the
`dev-witness-envelope` feature for local replay tests. Mock/local replay tests
must not be counted as production ZK/STARK coverage.
