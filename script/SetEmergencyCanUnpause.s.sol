/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Toggle whether `emergencyAuthority` can unpause.
/// @dev Must be executed by `rootAuthority`. Recommended production default is `0` (pause-only guardian).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_EMERGENCY_CAN_UNPAUSE` (0/1)
contract SetEmergencyCanUnpause {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bool canUnpause = vm.envUint("BLACKCAT_EMERGENCY_CAN_UNPAUSE") != 0;

        vm.startBroadcast(pk);
        InstanceController(controller).setEmergencyCanUnpause(canUnpause);
        vm.stopBroadcast();
    }
}
