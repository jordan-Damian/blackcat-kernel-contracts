/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Break-glass rollback via relayer (EIP-712 signed by `rootAuthority`).
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (relayer)
///    - `BLACKCAT_INSTANCE_CONTROLLER` (address)
///    - `BLACKCAT_ROLLBACK_DEADLINE` (uint256; included in signed digest)
///    - `BLACKCAT_ROLLBACK_SIGNATURE` (bytes; signature by `rootAuthority`)
/// 2) Run:
///    - `forge script script/RollbackToCompatibilityStateAuthorized.s.sol:RollbackToCompatibilityStateAuthorized --rpc-url <RPC> --broadcast`
contract RollbackToCompatibilityStateAuthorized {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        uint256 deadline = vm.envUint("BLACKCAT_ROLLBACK_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_ROLLBACK_SIGNATURE");

        vm.startBroadcast(pk);
        InstanceController(controller).rollbackToCompatibilityStateAuthorized(deadline, signature);
        vm.stopBroadcast();
    }
}
