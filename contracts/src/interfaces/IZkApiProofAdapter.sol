// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";

/// @title IZkApiProofAdapter – Proof verification boundary
/// @notice The vault delegates Groth16 verification to this boundary.
interface IZkApiProofAdapter {
    /// @notice Assert that a request proof is valid for the given public inputs.
    /// @dev Must revert if the proof is invalid.
    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proofEnvelope) external view;

    /// @notice Assert that a withdrawal proof is valid for the given public inputs.
    /// @dev Must revert if the proof is invalid.
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proofEnvelope)
        external
        view;
}
