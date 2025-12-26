/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Toggle `autoPauseOnBadCheckIn`.
/// @dev Env:
/// - `PRIVATE_KEY` (must be root authority EOA)
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_AUTO_PAUSE` (0/1)
contract SetAutoPauseOnBadCheckIn {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bool enabled = vm.envUint("BLACKCAT_AUTO_PAUSE") != 0;

        vm.startBroadcast(pk);
        InstanceController(controller).setAutoPauseOnBadCheckIn(enabled);
        vm.stopBroadcast();
    }
}
