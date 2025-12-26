/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Report an incident (direct call; will pause).
/// @dev Env:
/// - `PRIVATE_KEY` (must be root/emergency/reporter authority EOA)
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_INCIDENT_HASH`
contract ReportIncident {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bytes32 incidentHash = vm.envBytes32("BLACKCAT_INCIDENT_HASH");

        vm.startBroadcast(pk);
        InstanceController(controller).reportIncident(incidentHash);
        vm.stopBroadcast();
    }
}
