/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Deploy ReleaseRegistry.
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (deployer)
///    - `BLACKCAT_RELEASE_REGISTRY_OWNER` (registry owner; typically a Safe)
/// 2) Run:
///    - `forge script script/DeployReleaseRegistry.s.sol:DeployReleaseRegistry --rpc-url <RPC> --broadcast`
contract DeployReleaseRegistry {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (ReleaseRegistry registry) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address registryOwner = vm.envAddress("BLACKCAT_RELEASE_REGISTRY_OWNER");

        vm.startBroadcast(deployerPk);
        registry = new ReleaseRegistry(registryOwner);
        vm.stopBroadcast();
    }
}
