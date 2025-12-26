/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Permissionless safety: pause the controller if the active root is no longer trusted by `ReleaseRegistry`.
/// @dev Any sender can call; this can only reduce availability (pause) and records an incident.
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
contract PauseIfActiveRootUntrusted {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        vm.startBroadcast(pk);
        InstanceController(controller).pauseIfActiveRootUntrusted();
        vm.stopBroadcast();
    }
}

