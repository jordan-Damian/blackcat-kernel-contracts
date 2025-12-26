/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Publish a release into an existing ReleaseRegistry.
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (must be registry owner)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_COMPONENT_ID` (bytes32)
///    - `BLACKCAT_RELEASE_VERSION` (uint64 as uint env)
///    - `BLACKCAT_RELEASE_ROOT` (bytes32)
///    - `BLACKCAT_RELEASE_URI_HASH` (bytes32)
///    - `BLACKCAT_RELEASE_META_HASH` (bytes32; optional, set to 0x0 if unused)
/// 2) Run:
///    - `forge script script/PublishRelease.s.sol:PublishRelease --rpc-url <RPC> --broadcast`
contract PublishRelease {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        bytes32 componentId = vm.envBytes32("BLACKCAT_COMPONENT_ID");
        uint64 version = uint64(vm.envUint("BLACKCAT_RELEASE_VERSION"));
        bytes32 root = vm.envBytes32("BLACKCAT_RELEASE_ROOT");
        bytes32 uriHash = vm.envBytes32("BLACKCAT_RELEASE_URI_HASH");
        bytes32 metaHash = vm.envBytes32("BLACKCAT_RELEASE_META_HASH");

        vm.startBroadcast(deployerPk);
        ReleaseRegistry(registry).publish(componentId, version, root, uriHash, metaHash);
        vm.stopBroadcast();
    }
}
