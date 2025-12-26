/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Lock an attestation key (write-once behavior for a specific slot).
/// @dev Must be executed by `rootAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_ATTESTATION_KEY`
contract LockAttestationKey {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bytes32 key = vm.envBytes32("BLACKCAT_ATTESTATION_KEY");

        vm.startBroadcast(pk);
        InstanceController(controller).lockAttestationKey(key);
        vm.stopBroadcast();
    }
}
