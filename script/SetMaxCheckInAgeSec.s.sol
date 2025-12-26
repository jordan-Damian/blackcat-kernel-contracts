/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Set controller check-in freshness bound (`maxCheckInAgeSec`).
/// @dev Must be executed by `rootAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_MAX_CHECKIN_AGE_SEC`
contract SetMaxCheckInAgeSec {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        uint64 maxAgeSec = uint64(vm.envUint("BLACKCAT_MAX_CHECKIN_AGE_SEC"));

        vm.startBroadcast(pk);
        InstanceController(controller).setMaxCheckInAgeSec(maxAgeSec);
        vm.stopBroadcast();
    }
}

