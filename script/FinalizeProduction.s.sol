/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice One-shot helper to lock down a controller for production.
/// @dev Must be executed by `rootAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_RELEASE_REGISTRY`
/// - `BLACKCAT_EXPECTED_COMPONENT_ID` (bytes32)
/// - `BLACKCAT_MIN_UPGRADE_DELAY_SEC` (uint)
/// - `BLACKCAT_MAX_CHECKIN_AGE_SEC` (uint; must be non-zero for production)
/// - `BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN` (0/1)
/// - `BLACKCAT_COMPATIBILITY_WINDOW_SEC` (uint)
/// - `BLACKCAT_EMERGENCY_CAN_UNPAUSE` (0/1; recommended prod default: 0)
contract FinalizeProduction {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        address releaseRegistry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");
        bytes32 expectedComponentId = vm.envBytes32("BLACKCAT_EXPECTED_COMPONENT_ID");
        uint64 minUpgradeDelaySec = uint64(vm.envUint("BLACKCAT_MIN_UPGRADE_DELAY_SEC"));
        uint64 maxCheckInAgeSec = uint64(vm.envUint("BLACKCAT_MAX_CHECKIN_AGE_SEC"));
        bool autoPauseOnBadCheckIn = vm.envUint("BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN") != 0;
        uint64 compatibilityWindowSec = uint64(vm.envUint("BLACKCAT_COMPATIBILITY_WINDOW_SEC"));
        bool emergencyCanUnpause = vm.envUint("BLACKCAT_EMERGENCY_CAN_UNPAUSE") != 0;

        vm.startBroadcast(pk);
        InstanceController(controller)
            .finalizeProduction(
                releaseRegistry,
                expectedComponentId,
                minUpgradeDelaySec,
                maxCheckInAgeSec,
                autoPauseOnBadCheckIn,
                compatibilityWindowSec,
                emergencyCanUnpause
            );
        vm.stopBroadcast();
    }
}

