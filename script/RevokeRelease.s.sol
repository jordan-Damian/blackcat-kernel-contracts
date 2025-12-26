/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Revoke a release in an existing ReleaseRegistry.
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (must be registry owner)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_COMPONENT_ID` (bytes32)
///    - `BLACKCAT_RELEASE_VERSION` (uint64 as uint env)
/// 2) Run:
///    - `forge script script/RevokeRelease.s.sol:RevokeRelease --rpc-url <RPC> --broadcast`
contract RevokeRelease {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        bytes32 componentId = vm.envBytes32("BLACKCAT_COMPONENT_ID");
        uint64 version = uint64(vm.envUint("BLACKCAT_RELEASE_VERSION"));

        vm.startBroadcast(deployerPk);
        ReleaseRegistry(registry).revoke(componentId, version);
        vm.stopBroadcast();
    }
}
