# zkAPI

Anonymous prepaid API usage credits using zero-knowledge proofs.

## Overview

zkAPI lets users deposit ERC-20 tokens into an on-chain vault, use a private balance for off-chain API requests, and withdraw the remainder. Request proofs establish note membership and sufficient balance without revealing the note ID or balance.

The protocol uses a **state-anchor chain**: each request derives a nullifier from the current private state, and the server signs the next balance commitment and anchor. Nullifiers identify reused states, while rerandomized commitments hide the link between successive balances.

## Current implementation: v2

The active implementation on `main` uses **compact Groth16 proofs over BN254** for requests and withdrawals. It includes:

- Rust proof generation and verification, a persistent wallet SDK, shared types, and Merkle tree/indexer helpers.
- A browser/WASM wallet core for local request and withdrawal proving, with storage and transport supplied by the host application.
- A Solidity `ZkApiVault` with an on-chain `Groth16ProofAdapter`, mutual close, and escape withdrawals.
- Versioned proving/verifying keys and generated Solidity sources in [`setup/v2/`](setup/v2/).
- Deferred request settlement: applications can prepare and persist a proof, send it through their own transport, then complete the wallet transition when the response arrives.

The migration is partial. `zkapi-server` and `zkapi-cli` remain as legacy v1 source and are not members of the current Rust workspace. This checkout does not provide a runnable v2 HTTP server or CLI. Cairo/Stwo programs, XMSS/WOTS+ helpers, and the older wallet source remain in the tree; the active wallet is [`wallet_v2.rs`](rust/crates/zkapi-client/src/wallet_v2.rs), exported as `zkapi_client::wallet`.

[`PROTOCOL.md`](PROTOCOL.md), [`SPEC.md`](SPEC.md), and much of the [implementation book](docs/src/intro.md) describe the earlier v1 design. Use them as design background; the v2 source and setup artifacts define the current implementation.

## Architecture

```text
contracts/        Solidity v2 vault, BN254 Poseidon, and Groth16 verifier
setup/v2/         Selected request/withdrawal keys, manifest, generated Solidity
rust/             Rust workspace
  crates/
    zkapi-types   Shared types, v2 public inputs, wire formats, serialization
    zkapi-core    BN254 Poseidon, Merkle tree, leaf and nullifier helpers
    zkapi-crypto  Retained v1 Stark-curve Pedersen and XMSS/WOTS+ helpers
    zkapi-proof   Groth16 circuits, compact proof API, v2 curve operations
    zkapi-client  V2 wallet, request journal, recovery, withdrawal proofs
    zkapi-browser Browser/WASM wallet core and reusable request prover
    zkapi-indexer Merkle tree mirror and read-service helpers
    zkapi-server  Legacy v1 server source (outside the workspace)
    zkapi-cli     Legacy v1 CLI source (outside the workspace)
cairo/            Retained v1 Cairo proof programs
scripts/          Cairo/Stwo proof scripts and maintenance checks
docs/             Implementation book (primarily v1)
```

## Request and withdrawal flows

### Requests and deferred settlement

The wallet takes the current active root and a 32-level Merkle path supplied by the caller. Its request proof binds a nullifier, request-context authorization tag, rerandomized balance commitment, and solvency bound to the deployment and its state-signing key.

For applications that control transport or receive responses asynchronously:

1. `Wallet::prepare_request(...)` builds an `ApiRequestV2` and persists the complete prepared request in `pending_journal.json` before returning it.
2. The application sends the request. `Wallet::pending_api_request()` retrieves the same proof and request ID for an idempotent transport retry.
3. `Wallet::complete_pending_response(...)` validates the response, charge, next commitment, anchor, and server signature, saves the new note state, and clears the pending journal.

`Wallet::request_flow(...)` wraps preparation, an HTTP POST to `/v2/requests`, and completion. `Wallet::recover()` checks `GET /v2/requests/{client_request_id}` and applies a finalized response when available. A pending journal prevents preparation of another request until the outstanding request is resolved. `clear_pending_request()` is for an explicit server rejection before nullifier reservation; transport uncertainty should retain the journal for retry or recovery.

The [v2 wire types](rust/crates/zkapi-types/src/wire.rs) also define prompt-free OpenRouter lease authorization, short-lived key responses, and recovery metadata without the plaintext key for deferred integrations. These types do not supply a server implementation.

### Browser wallet

[`zkapi-browser`](rust/crates/zkapi-browser/src/lib.rs) exposes the v2 wallet core through Rust functions and `wasm-bindgen` exports. It generates deposit parameters, builds Merkle paths from tree snapshots, prepares request proofs, verifies completed responses, and prepares mutual-close or escape-withdrawal proofs.

The browser core accepts state snapshots and returns updated state or a prepared request with its journal. The host application supplies persistence, HTTP transport, request IDs, and timestamps. It must persist the prepared request and journal before sending, prevent another request while one is pending, then atomically save the returned state and clear the journal after completion. No browser UI or IndexedDB integration is included.

Browser response completion checks the charge against the pending proof's `solvency_bound`, allowing settlement up to the budget authorized for that request.

Proving keys are supplied as bytes. `BrowserRequestProver` retains a decoded request proving key for repeated requests; `RequestProver::from_bytes(...)` and `WithdrawalProver::from_bytes(...)` also expose byte-based loading in the compact proof API.

### Withdrawals

- **Mutual close:** a withdrawal proof with server clearance closes the note immediately. The vault pays the remaining balance to the destination and the spent portion to the operator treasury.
- **Escape withdrawal:** a proof without clearance removes the note from the active tree and starts the deployment's **challenge period**. The constructor requires a nonzero `challengePeriod`, which is immutable; `DEFAULT_CHALLENGE_PERIOD` is 24 hours, but callers must pass the duration explicitly. A valid request proof using the pending withdrawal's nullifier and saved root can challenge the withdrawal and restore the note. Anyone can finalize an unchallenged withdrawal after the deadline; funds go to its recorded destination and the treasury.
- **Expiry:** an expired active note can be claimed into the treasury.

The vault binds proofs to protocol version `2`, chain ID, contract address, and immutable server signing keys. See [`ZkApiVault.sol`](contracts/src/ZkApiVault.sol) for the contract interface.

## Cryptography and setup

| Component | Active v2 implementation |
|-----------|--------------------------|
| Proof system | Circuit-specific Groth16 over BN254 |
| Proof encoding | 256 raw bytes; base64 in the JSON proof envelope |
| Hashing | Poseidon over the BN254 scalar field |
| Active-note tree | Depth 32, with matching Rust and Solidity hashing |
| Balance commitments | Pedersen commitments on Baby-JubJub |
| State and clearance signatures | Baby-JubJub Schnorr signatures with Poseidon challenges |
| Nullifiers | `Poseidon(domain("zkapi.v2.null"), secret, anchor)` |

V2 is **not post-quantum secure**: its proof system, signatures, and commitments rely on elliptic-curve cryptography. The earlier Cairo/STARK and XMSS security model applies to the retained v1 code.

[`setup/v2/`](setup/v2/) contains `request.pk`, `request.vk`, `withdrawal.pk`, `withdrawal.vk`, a `manifest.json`, and generated Solidity verifier/Poseidon sources. Clients and verifiers must use the keys matching the deployed `Groth16ProofAdapter`. Set `ClientProofMode::Groth16 { setup_dir: ... }` to that directory and configure the deployment's chain ID, contract address, signing keys, and charge policy.

`zkapi_proof::compact::setup(...)` generates a fresh circuit-specific trusted setup and Solidity sources. Regenerating keys changes the verifier; it is not a routine client setup step. The checked-in artifacts do not document a multiparty setup ceremony.

V2 domain tags include `zkapi.v2.reg`, `.leaf`, `.node`, `.null`, `.auth`, `.state`, `.clear`, `.withdraw`, `.anchor`, and `.blind`. Their definitions are in [`zkapi-core/src/v2.rs`](rust/crates/zkapi-core/src/v2.rs).

## Building and checking

Run each block from the repository root. Rust requires a Rust toolchain with Cargo. Solidity requires Foundry; [`foundry.toml`](contracts/foundry.toml) pins Solidity `0.8.28` and enables optimization through IR.

Initialize the Solidity dependencies after cloning:

```bash
git submodule update --init --recursive
```

### Rust

```bash
cargo build --manifest-path rust/Cargo.toml --workspace --locked
cargo test --manifest-path rust/Cargo.toml --workspace --release --locked
```

These commands cover the seven workspace members listed above. Release mode is useful for the Groth16 proof tests.

To generate and locally verify sample request and withdrawal proofs using the checked-in setup, then print their public inputs and Solidity proof bytes as JSON:

```bash
cargo run --manifest-path rust/Cargo.toml --release --locked \
  -p zkapi-proof --example solidity_fixture -- setup/v2
```

The [`proof_bench`](rust/crates/zkapi-proof/examples/proof_bench.rs) example reports key-loading, proving, and verification timings, circuit sizes, and proof sizes as JSON:

```bash
cargo run --manifest-path rust/Cargo.toml --release --locked \
  -p zkapi-proof --example proof_bench -- setup/v2 request_genesis 5 1
```

Arguments are `SETUP_DIRECTORY CASE ITERATIONS WARMUP_ITERATIONS [LOAD_ITERATIONS]`. Cases are `request_genesis`, `request_state`, `withdrawal_genesis_escape`, `withdrawal_genesis_mutual`, `withdrawal_state_escape`, and `withdrawal_state_mutual`.

### Browser/WASM library

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path rust/Cargo.toml --release --locked \
  -p zkapi-browser --target wasm32-unknown-unknown
```

This produces `rust/target/wasm32-unknown-unknown/release/zkapi_browser.wasm`. Use the host application's `wasm-bindgen` packaging step to generate JavaScript bindings, and supply the matching `setup/v2/request.pk` and `withdrawal.pk` bytes when proving.

### Solidity

```bash
forge build --root contracts
forge test --root contracts
```

The tests include verification of Rust-generated request and withdrawal proof fixtures, rejection of changed public inputs, a BN254 Poseidon vector, vault deposit/mutual-close settlement, and escape-withdrawal deadline enforcement and finalization.

### Legacy Cairo programs

Cairo is optional for the active v2 Rust/Solidity flow. The retained package uses Cairo dependencies at `2.16.1`; use a compatible Scarb toolchain to build or test it:

```bash
cd cairo
scarb build
scarb test
```

The [Stwo notes](docs/src/stwo.md) and `scripts/prove_*_stwo.sh` cover the older proving flow. They are not required to generate v2 Groth16 proofs.

## License

MIT OR Apache-2.0
