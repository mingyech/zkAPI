// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {ZkApiVault} from "../src/ZkApiVault.sol";
import {MockProofAdapter} from "../src/adapters/MockProofAdapter.sol";

/// @title DemoBillingToken – billing token for the local demo.
/// @notice Uses 3 decimals (not the ERC20 default of 18) so the protocol's
///         integer credit amounts render as human-friendly values in wallets:
///         e.g. a 2000-credit deposit shows as "2.000" in MetaMask instead of
///         18-decimal dust ("<0.000001"). Exposes a public `mint` for funding.
contract DemoBillingToken is ERC20 {
    constructor() ERC20("zkAPI Demo Credit", "ZKAPI") {}

    function decimals() public pure override returns (uint8) {
        return 3;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title DeployScript – Local demo deployment for the zkAPI stack.
/// @notice Used by scripts/e2e-demo.sh. Deploys an ERC20 billing token, a
///         permissive MockProofAdapter, and the ZkApiVault, then writes a
///         deployment manifest JSON to $OUTPUT_PATH with the exact keys the
///         demo harness reads: {vault, billingToken, noteTtl}.
/// @dev    Reads three environment variables:
///           PRIVATE_KEY  – deployer key (becomes vault owner + treasury).
///           MINT_AMOUNT  – billing tokens minted to the deployer (depositor).
///           OUTPUT_PATH  – absolute path for the deployment manifest JSON.
///         The vault owner MUST be the deployer so the demo's onlyOwner
///         `rotateServerRoots` cast (sent with the same key) succeeds.
contract DeployScript is Script {
    // Demo parameters. The charge caps are informational on-chain (the caps
    // that actually gate flows are enforced in the off-chain server / Cairo),
    // so these mirror test/ZkApiVault.t.sol rather than the daemon flags.
    uint64 internal constant NOTE_TTL = 30 days;
    uint128 internal constant REQUEST_CHARGE_CAP = 1 ether;
    uint128 internal constant POLICY_CHARGE_CAP = 0.5 ether;
    bool internal constant POLICY_ENABLED = true;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        uint256 mintAmount = vm.envOr("MINT_AMOUNT", uint256(0));
        string memory outputPath = vm.envString("OUTPUT_PATH");
        address deployer = vm.addr(deployerKey);
        // Treasury (receives the operator's consumed amount on settlement). Kept
        // SEPARATE from the deployer/depositor so the consumed amount visibly
        // leaves the depositor's wallet. Defaults to anvil account #1.
        address treasury =
            vm.envOr("TREASURY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8));

        vm.startBroadcast(deployerKey);

        // 1. Billing token (3 decimals; see DemoBillingToken). Exposes a public
        //    mint(); fund the deployer, who is also the depositor in the demo.
        DemoBillingToken billingToken = new DemoBillingToken();
        if (mintAmount > 0) {
            billingToken.mint(deployer, mintAmount);
        }

        // 2. Permissive proof adapter (acceptAll = true). The demo verifies
        //    plumbing, not STARK soundness.
        MockProofAdapter proofAdapter = new MockProofAdapter();

        // 3. The settlement vault. owner == deployer (so the demo's onlyOwner
        //    rotateServerRoots cast succeeds); treasury is a separate account.
        ZkApiVault vault = new ZkApiVault(
            address(billingToken),
            treasury, // treasury (separate from deployer)
            NOTE_TTL,
            REQUEST_CHARGE_CAP,
            POLICY_CHARGE_CAP,
            POLICY_ENABLED,
            address(proofAdapter),
            deployer // owner
        );

        vm.stopBroadcast();

        // Emit the manifest the demo harness reads via jq (.vault /
        // .billingToken / .noteTtl).
        string memory manifest = "deployment";
        vm.serializeAddress(manifest, "vault", address(vault));
        vm.serializeAddress(manifest, "billingToken", address(billingToken));
        vm.serializeAddress(manifest, "treasury", treasury);
        string memory serialized = vm.serializeUint(manifest, "noteTtl", uint256(NOTE_TTL));
        vm.writeJson(serialized, outputPath);

        console2.log("vault       ", address(vault));
        console2.log("billingToken", address(billingToken));
        console2.log("treasury    ", treasury);
        console2.log("proofAdapter", address(proofAdapter));
        console2.log("noteTtl     ", uint256(NOTE_TTL));
        console2.log("manifest    ", outputPath);
    }
}
