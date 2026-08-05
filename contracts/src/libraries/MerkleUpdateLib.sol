// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Errors} from "./Errors.sol";
import {StarkPoseidon} from "./StarkPoseidon.sol";

/// @title MerkleUpdateLib – Fixed-depth binary Merkle tree helpers
/// @notice Uses the same Starknet/Cairo-compatible Poseidon hash as the Rust
///         and Cairo implementations.
library MerkleUpdateLib {
    /// @notice Depth of the active-note Merkle tree.
    uint256 internal constant MERKLE_DEPTH = 32;

    /// @notice The Stark field prime: P = 2^251 + 17 * 2^192 + 1.
    uint256 internal constant STARK_FIELD_PRIME =
        3618502788666131213697322783095070105623107215331596699973092056135872020481;

    /// @notice Domain separator for node hashing.
    ///         domain("zkapi.node") = big-endian integer of ASCII bytes.
    ///         "zkapi.node" = 0x7a6b6170692e6e6f6465
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e6e6f6465;

    /// @notice Compute a Merkle node hash.
    function poseidonNodeHash(uint256 domain, uint256 left, uint256 right) internal pure returns (uint256) {
        return StarkPoseidon.hash3(domain, left, right);
    }

    /// @notice Compute the Merkle root from a leaf and its sibling path.
    /// @param index  The leaf index (note_id).
    /// @param leaf   The leaf value.
    /// @param siblings  The 32 sibling hashes from leaf to root.
    /// @return root  The computed Merkle root.
    function computeRoot(uint32 index, uint256 leaf, uint256[32] calldata siblings)
        internal
        pure
        returns (uint256 root)
    {
        root = leaf;
        uint32 idx = index;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            if (idx & 1 == 0) {
                root = poseidonNodeHash(DOMAIN_NODE, root, siblings[i]);
            } else {
                root = poseidonNodeHash(DOMAIN_NODE, siblings[i], root);
            }
            idx >>= 1;
        }
    }

    /// @notice Verify that the current root matches (index, oldLeaf, siblings),
    ///         then compute the new root after replacing oldLeaf with newLeaf.
    /// @param currentRoot The expected current Merkle root.
    /// @param index       The leaf index.
    /// @param oldLeaf     The current leaf value at `index`.
    /// @param newLeaf     The replacement leaf value.
    /// @param siblings    The 32 sibling hashes.
    /// @return newRoot    The Merkle root after replacement.
    function verifyAndUpdate(
        uint256 currentRoot,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings
    ) internal pure returns (uint256 newRoot) {
        uint256 computedOldRoot;
        (computedOldRoot, newRoot) = StarkPoseidon.hash3PairPath32(DOMAIN_NODE, index, oldLeaf, newLeaf, siblings);
        if (computedOldRoot != currentRoot) {
            revert Errors.StaleRoot();
        }
    }
}
