/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Set controller upgrade timelock (`minUpgradeDelaySec`).
/// @dev Env:
/// - `PRIVATE_KEY` (must be root authority EOA)
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_MIN_UPGRADE_DELAY_SEC`
contract SetMinUpgradeDelay {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        uint64 delaySec = uint64(vm.envUint("BLACKCAT_MIN_UPGRADE_DELAY_SEC"));

        vm.startBroadcast(pk);
        InstanceController(controller).setMinUpgradeDelaySec(delaySec);
        vm.stopBroadcast();
    }
}
