// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Errors} from "./Errors.sol";
import {Bn254Poseidon} from "./Bn254Poseidon.sol";

library MerkleUpdateLib {
    uint256 internal constant MERKLE_DEPTH = 32;
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"

    function poseidonNodeHash(uint256 left, uint256 right) internal pure returns (uint256) {
        return Bn254Poseidon.hash3(DOMAIN_NODE, left, right);
    }

    function computeRoot(uint32 index, uint256 leaf, uint256[32] calldata siblings)
        internal
        pure
        returns (uint256 root)
    {
        root = leaf;
        for (uint256 level = 0; level < MERKLE_DEPTH;) {
            root = (((index >> level) & 1) == 0)
                ? poseidonNodeHash(root, siblings[level])
                : poseidonNodeHash(siblings[level], root);
            unchecked {
                ++level;
            }
        }
    }

    function verifyAndUpdate(
        uint256 currentRoot,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings
    ) internal pure returns (uint256 newRoot) {
        uint256 computedOldRoot;
        (computedOldRoot, newRoot) = Bn254Poseidon.hash3PairPath32(DOMAIN_NODE, index, oldLeaf, newLeaf, siblings);
        if (computedOldRoot != currentRoot) revert Errors.StaleRoot();
    }
}
