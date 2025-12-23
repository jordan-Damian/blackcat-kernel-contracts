pragma solidity ^0.8.24;

import {InstanceFactory} from "../src/InstanceFactory.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Create a per-install InstanceController using CREATE2 (deterministic).
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

        vm.startBroadcast(deployerPk);
        instance = InstanceFactory(factory)
            .createInstanceDeterministic(
                rootAuthority,
                upgradeAuthority,
                emergencyAuthority,
                genesisRoot,
                genesisUriHash,
                genesisPolicyHash,
                salt
            );
        vm.stopBroadcast();
    }
}

