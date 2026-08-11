// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Events – All events emitted by ZkApiVault
abstract contract Events {
    event NoteDeposited(
        uint32 indexed noteId, bytes32 indexed commitment, uint128 amount, uint64 expiryTs, uint256 newRoot
    );

    event MutualClose(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination);

    event EscapeWithdrawalInitiated(
        uint32 indexed noteId,
        uint256 nullifier,
        uint128 finalBalance,
        address destination,
        uint64 challengeDeadline,
        uint256 newRoot
    );

    event EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier, uint256 restoredRoot);

    event EscapeWithdrawalFinalized(
        uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination
    );

    event ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount, uint256 newRoot);

    event ProofAdapterSet(address indexed newAdapter);

    event TreasurySet(address indexed newTreasury);
}
