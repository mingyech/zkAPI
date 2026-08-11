// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Bn254Poseidon} from "./Bn254Poseidon.sol";

library NoteLeafLib {
    uint256 internal constant DOMAIN_LEAF = 0x7a6b6170692e76322e6c656166; // "zkapi.v2.leaf"

    function computeLeaf(uint32 noteId, bytes32 commitment, uint128 depositAmount, uint64 expiryTs)
        internal
        pure
        returns (uint256)
    {
        return Bn254Poseidon.hash5(
            DOMAIN_LEAF, uint256(noteId), uint256(commitment), uint256(depositAmount), uint256(expiryTs)
        );
    }
}
