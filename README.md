# Note-binding repair candidate

This revision binds signed balances to the private membership leaf. It is
incompatible with earlier v2 setups and deployed verifiers; see
[setup compatibility](setup/v2/README.md). The v2 wire format is unchanged.

# zkAPI

Anonymous prepaid API usage credits using zero-knowledge proofs.

## Overview

zkAPI lets users deposit funds on-chain once, then make many anonymous off-chain API requests. The server is protected against replay and non-payment, while honest users remain unlinkable.

The protocol uses a **state-anchor chain**: each valid request consumes the user's current private state and yields a fresh next state signed by the server.

See [PROTOCOL.md](PROTOCOL.md) for the full protocol description and [SPEC.md](SPEC.md) for implementation details.

## Architecture

```
cairo/          - ZK proof programs (request + withdrawal)
contracts/      - Solidity settlement contract (ZkApiVault)
rust/           - Off-chain Rust implementation
  crates/
    zkapi-types   - Shared types, serialization, domain constants
    zkapi-core    - Poseidon hash, Merkle tree, nullifier, leaf helpers
    zkapi-crypto  - Pedersen commitment, XMSS/WOTS+ signatures
    zkapi-proof   - Proof generation/verification orchestration
    zkapi-client  - Client wallet, note lifecycle, recovery
    zkapi-server  - Server: proof verification, nullifier store, signing
    zkapi-indexer  - Merkle tree mirror from on-chain events
    zkapi-cli     - Command-line interface
```

## Post-Quantum Security Model

The protocol is post-quantum wherever practical:

- **Proof system**: Cairo STARK proofs (PQ-secure)
- **Hash function**: Poseidon over the Stark field (PQ-secure)
- **Merkle tree**: Poseidon-based (PQ-secure)
- **Server signatures**: XMSS hash-based signatures using Poseidon WOTS+ (PQ-secure)
- **Nullifiers**: Poseidon-derived (PQ-secure)

**Exception**: The Pedersen balance commitment uses elliptic curve operations on the Stark curve. This is the single accepted non-PQ component in v1, required for homomorphic addition and rerandomization. This exception is isolated to the `pedersen_balance` module in Cairo and `zkapi-crypto/pedersen` in Rust.

## Building

### Rust

```bash
cd rust
cargo build
cargo test
```

### Solidity

```bash
cd contracts
forge build
forge test
```

### Cairo

```bash
cd cairo
scarb build
```

## Key Cryptographic Choices

- **Field**: Stark field `felt252`
- **Hash**: Poseidon builtin (domain-separated)
- **Balance commitment**: Pedersen on Stark curve: `E(B, r) = B * G_balance + r * H_blind`
- **Server signatures**: XMSS with WOTS+ (w=16, n=248 bits, tree height=20)
- **Nullifiers**: `x = Poseidon(domain("zkapi.null"), secret, anchor)`

All Poseidon invocations use domain separation tags. No unlabeled hash invocation exists in the codebase.

## Domain Tags

| Label | Usage |
|-------|-------|
| `zkapi.reg` | Registration commitment |
| `zkapi.leaf` | Active note leaf |
| `zkapi.node` | Merkle tree internal node |
| `zkapi.null` | Nullifier derivation |
| `zkapi.state` | State signature message |
| `zkapi.clear` | Clearance signature message |
| `zkapi.anchor` | Next anchor derivation |
| `zkapi.blind` | Blind delta derivation |
| `zkapi.xmss.*` | XMSS/WOTS+ internal hashing |

## License

MIT OR Apache-2.0
