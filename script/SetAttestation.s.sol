/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Set an attestation slot in the controller.
/// @dev Env:
/// - `PRIVATE_KEY` (must be root authority EOA)
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_ATTESTATION_KEY`
/// - `BLACKCAT_ATTESTATION_VALUE`
contract SetAttestation {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bytes32 key = vm.envBytes32("BLACKCAT_ATTESTATION_KEY");
        bytes32 value = vm.envBytes32("BLACKCAT_ATTESTATION_VALUE");

        vm.startBroadcast(pk);
        InstanceController(controller).setAttestation(key, value);
        vm.stopBroadcast();
    }
}
