/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {KernelAuthority} from "../src/KernelAuthority.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Deploy a KernelAuthority threshold signer (multi-device by design).
/// @dev Env:
/// - `PRIVATE_KEY` (deployer)
/// - `BLACKCAT_KERNEL_SIGNER_1`
/// - `BLACKCAT_KERNEL_SIGNER_2`
/// - `BLACKCAT_KERNEL_SIGNER_3`
/// - `BLACKCAT_KERNEL_THRESHOLD`
contract DeployKernelAuthority {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (KernelAuthority authority) {
        uint256 pk = vm.envUint("PRIVATE_KEY");

        address signer1 = vm.envAddress("BLACKCAT_KERNEL_SIGNER_1");
        address signer2 = vm.envAddress("BLACKCAT_KERNEL_SIGNER_2");
        address signer3 = vm.envAddress("BLACKCAT_KERNEL_SIGNER_3");
        uint256 threshold = vm.envUint("BLACKCAT_KERNEL_THRESHOLD");

        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;

        vm.startBroadcast(pk);
        authority = new KernelAuthority(signers, threshold);
        vm.stopBroadcast();
    }
}

