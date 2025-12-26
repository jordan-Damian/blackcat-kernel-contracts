/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceFactory} from "../src/InstanceFactory.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Deploy InstanceFactory.
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (deployer)
///    - `BLACKCAT_RELEASE_REGISTRY` (optional; set to 0x0 to disable trust enforcement)
/// 2) Run:
///    - `forge script script/DeployInstanceFactory.s.sol:DeployInstanceFactory --rpc-url <RPC> --broadcast`
contract DeployInstanceFactory {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (InstanceFactory factory) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        vm.startBroadcast(deployerPk);
        factory = new InstanceFactory(registry);
        vm.stopBroadcast();
    }
}
