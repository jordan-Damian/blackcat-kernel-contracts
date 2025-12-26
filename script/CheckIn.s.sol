/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Reporter check-in (direct call).
/// @dev Env:
/// - `PRIVATE_KEY` (must be reporter authority EOA)
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_OBSERVED_ROOT`
/// - `BLACKCAT_OBSERVED_URI_HASH`
/// - `BLACKCAT_OBSERVED_POLICY_HASH`
contract CheckIn {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        bytes32 observedRoot = vm.envBytes32("BLACKCAT_OBSERVED_ROOT");
        bytes32 observedUriHash = vm.envBytes32("BLACKCAT_OBSERVED_URI_HASH");
        bytes32 observedPolicyHash = vm.envBytes32("BLACKCAT_OBSERVED_POLICY_HASH");

        vm.startBroadcast(pk);
        InstanceController(controller).checkIn(observedRoot, observedUriHash, observedPolicyHash);
        vm.stopBroadcast();
    }
}
