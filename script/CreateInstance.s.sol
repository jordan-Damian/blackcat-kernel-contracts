/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceFactory} from "../src/InstanceFactory.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Create a per-install InstanceController (non-deterministic) via `InstanceFactory.createInstance(...)`.
/// @dev This is the simplest path and is primarily intended for dev/dry-run testing.
///
/// Env:
/// - `PRIVATE_KEY` (tx sender)
/// - `BLACKCAT_INSTANCE_FACTORY` (address)
/// - `BLACKCAT_ROOT_AUTHORITY` (address; EOA/Safe/KernelAuthority)
/// - `BLACKCAT_UPGRADE_AUTHORITY` (address; EOA/Safe/KernelAuthority)
/// - `BLACKCAT_EMERGENCY_AUTHORITY` (address; EOA/Safe/KernelAuthority)
/// - `BLACKCAT_GENESIS_ROOT` (bytes32; must be trusted in ReleaseRegistry if the factory was deployed with a registry)
/// - `BLACKCAT_GENESIS_URI_HASH` (bytes32)
/// - `BLACKCAT_GENESIS_POLICY_HASH` (bytes32)
contract CreateInstance {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (address instance) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address factory = vm.envAddress("BLACKCAT_INSTANCE_FACTORY");

        address rootAuthority = vm.envAddress("BLACKCAT_ROOT_AUTHORITY");
        address upgradeAuthority = vm.envAddress("BLACKCAT_UPGRADE_AUTHORITY");
        address emergencyAuthority = vm.envAddress("BLACKCAT_EMERGENCY_AUTHORITY");

        bytes32 genesisRoot = vm.envBytes32("BLACKCAT_GENESIS_ROOT");
        bytes32 genesisUriHash = vm.envBytes32("BLACKCAT_GENESIS_URI_HASH");
        bytes32 genesisPolicyHash = vm.envBytes32("BLACKCAT_GENESIS_POLICY_HASH");

        vm.startBroadcast(deployerPk);
        instance = InstanceFactory(factory)
            .createInstance(
                rootAuthority, upgradeAuthority, emergencyAuthority, genesisRoot, genesisUriHash, genesisPolicyHash
            );
        vm.stopBroadcast();
    }
}

