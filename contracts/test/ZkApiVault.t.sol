// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";

contract AcceptAllProofAdapter is IZkApiProofAdapter {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract ZkApiVaultTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint256 constant STATE_X = 11;
    uint256 constant STATE_Y = 12;
    uint256 constant CLEAR_X = 13;
    uint256 constant CLEAR_Y = 14;

    ERC20Mock token;
    AcceptAllProofAdapter adapter;
    ZkApiVault vault;
    address user = address(0x1234);
    address treasury = address(0x5678);
    uint256[32] emptySiblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        token = new ERC20Mock();
        adapter = new AcceptAllProofAdapter();
        vault = new ZkApiVault(
            address(token),
            treasury,
            30 days,
            100_000,
            address(adapter),
            STATE_X,
            STATE_Y,
            CLEAR_X,
            CLEAR_Y,
            address(this)
        );
        token.mint(user, DEPOSIT);
        vm.prank(user);
        token.approve(address(vault), type(uint256).max);
    }

    function test_depositAndMutualClose() public {
        vm.prank(user);
        vault.deposit(bytes32(uint256(42)), DEPOSIT, emptySiblings);
        uint256 depositedRoot = vault.currentRoot();

        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: depositedRoot,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: 0,
            finalBalance: 700_000,
            destination: user,
            withdrawalNullifier: 99,
            hasClearance: true,
            withdrawalTag: 100
        });
        vault.mutualClose(inputs, "", emptySiblings);
        assertEq(token.balanceOf(user), 700_000);
        assertEq(token.balanceOf(treasury), 300_000);
        assertTrue(vault.usedNullifiers(99));
    }
}
