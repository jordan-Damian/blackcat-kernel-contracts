/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Start an emergency authority transfer (2-step).
/// @dev Must be executed by `rootAuthority`.
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_NEW_EMERGENCY_AUTHORITY`
contract StartEmergencyAuthorityTransfer {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        address newAuthority = vm.envAddress("BLACKCAT_NEW_EMERGENCY_AUTHORITY");

        vm.startBroadcast(pk);
        InstanceController(controller).startEmergencyAuthorityTransfer(newAuthority);
        vm.stopBroadcast();
    }
}
