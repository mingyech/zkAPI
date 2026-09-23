# Note-bound development setup

Circuit ID: `zkapi-v2-note-bound-v1`.

These are new single-party development keys generated with OS randomness by
`cargo run --release -p zkapi-proof --example setup -- NEW_OUTPUT_DIRECTORY`.
The existing v2 directory name denotes the wire schema, not compatibility
with the previous setup. Proving/verifying files have a circuit revision header.
The matching generated Solidity verifier is committed alongside them.

This is not a reviewed setup ceremony. Matching hashes establish artifact
identity, not the absence of retained setup secrets. The circuit, third
Pedersen generator, and setup require independent review before production.
Do not replace live deployment files with these keys: deploy a fresh verifier
and vault and migrate clients/funds explicitly. Old signed states are not
compatible; preserve their original wallet data for legacy recovery.
