pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Revoke a release in an existing ReleaseRegistry via a relayer (EIP-712 signed by the registry owner).
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (relayer)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_COMPONENT_ID` (bytes32)
///    - `BLACKCAT_RELEASE_VERSION` (uint64 as uint env)
///    - `BLACKCAT_RELEASE_ROOT` (bytes32; must match the published release root)
///    - `BLACKCAT_RELEASE_REVOKE_DEADLINE` (uint256; included in signed digest)
///    - `BLACKCAT_RELEASE_REVOKE_SIGNATURE` (bytes; signature by registry owner)
/// 2) Run:
///    - `forge script script/RevokeReleaseAuthorized.s.sol:RevokeReleaseAuthorized --rpc-url <RPC> --broadcast`
contract RevokeReleaseAuthorized {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 relayerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        bytes32 componentId = vm.envBytes32("BLACKCAT_COMPONENT_ID");
        uint64 version = uint64(vm.envUint("BLACKCAT_RELEASE_VERSION"));
        bytes32 root = vm.envBytes32("BLACKCAT_RELEASE_ROOT");

        uint256 deadline = vm.envUint("BLACKCAT_RELEASE_REVOKE_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_RELEASE_REVOKE_SIGNATURE");

        vm.startBroadcast(relayerPk);
        ReleaseRegistry(registry).revokeAuthorized(componentId, version, root, deadline, signature);
        vm.stopBroadcast();
    }
}

