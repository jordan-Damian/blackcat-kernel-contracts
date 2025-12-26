/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceFactory} from "../src/InstanceFactory.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Create a per-install InstanceController using CREATE2 (deterministic) via an authorized setup ceremony.
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (deployer)
///    - `BLACKCAT_INSTANCE_FACTORY` (address)
///    - `BLACKCAT_ROOT_AUTHORITY` (address; EOA/Safe/KernelAuthority)
///    - `BLACKCAT_UPGRADE_AUTHORITY` (address; EOA/Safe/KernelAuthority)
///    - `BLACKCAT_EMERGENCY_AUTHORITY` (address; EOA/Safe/KernelAuthority)
///    - `BLACKCAT_GENESIS_ROOT` (bytes32)
///    - `BLACKCAT_GENESIS_URI_HASH` (bytes32)
///    - `BLACKCAT_GENESIS_POLICY_HASH` (bytes32)
///    - `BLACKCAT_INSTANCE_SALT` (bytes32)
///    - `BLACKCAT_SETUP_DEADLINE` (uint256; included in the signed digest)
///    - `BLACKCAT_SETUP_SIGNATURE` (bytes; signature by `BLACKCAT_ROOT_AUTHORITY`, EOA `(r,s,v)`/EIP-2098 or EIP-1271 blob)
/// 2) Run:
///    - `forge script script/CreateInstanceDeterministic.s.sol:CreateInstanceDeterministic --rpc-url <RPC> --broadcast`
contract CreateInstanceDeterministic {
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

        bytes32 salt = vm.envBytes32("BLACKCAT_INSTANCE_SALT");
        uint256 deadline = vm.envUint("BLACKCAT_SETUP_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_SETUP_SIGNATURE");

        vm.startBroadcast(deployerPk);
        instance = InstanceFactory(factory)
            .createInstanceDeterministicAuthorized(
                rootAuthority,
                upgradeAuthority,
                emergencyAuthority,
                genesisRoot,
                genesisUriHash,
                genesisPolicyHash,
                salt,
                deadline,
                signature
            );
        vm.stopBroadcast();
    }
}
