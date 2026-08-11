// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";

contract Bn254PoseidonTest is Test {
    function test_matchesRustVectors() public pure {
        assertEq(Bn254Poseidon.hash3(1, 2, 3), 0x1e706b0afc828a5262be1773734e80df7fa9c0aa25c8fd5dfb008122a62e65ca);
        assertEq(Bn254Poseidon.hash5(1, 2, 3, 4, 5), 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457);
    }
}
