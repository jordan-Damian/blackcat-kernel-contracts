/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Cancel the pending upgrade with exact `{root, uriHash, policyHash}` match.
/// @dev Can be executed by `rootAuthority` or `upgradeAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_UPGRADE_ROOT`
/// - `BLACKCAT_UPGRADE_URI_HASH`
/// - `BLACKCAT_UPGRADE_POLICY_HASH`
contract CancelUpgradeExpected {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        bytes32 root = vm.envBytes32("BLACKCAT_UPGRADE_ROOT");
        bytes32 uriHash = vm.envBytes32("BLACKCAT_UPGRADE_URI_HASH");
        bytes32 policyHash = vm.envBytes32("BLACKCAT_UPGRADE_POLICY_HASH");

        vm.startBroadcast(pk);
        InstanceController(controller).cancelUpgradeExpected(root, uriHash, policyHash);
        vm.stopBroadcast();
    }
}
