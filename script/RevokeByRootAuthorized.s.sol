pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Revoke a release by `root` via a relayer (EIP-712 signed by the registry owner).
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (relayer)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_RELEASE_ROOT` (bytes32; published root)
///    - `BLACKCAT_RELEASE_REVOKE_BY_ROOT_DEADLINE` (uint256; included in signed digest)
///    - `BLACKCAT_RELEASE_REVOKE_BY_ROOT_SIGNATURE` (bytes; signature by registry owner)
/// 2) Run:
///    - `forge script script/RevokeByRootAuthorized.s.sol:RevokeByRootAuthorized --rpc-url <RPC> --broadcast`
contract RevokeByRootAuthorized {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 relayerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        bytes32 root = vm.envBytes32("BLACKCAT_RELEASE_ROOT");
        uint256 deadline = vm.envUint("BLACKCAT_RELEASE_REVOKE_BY_ROOT_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_RELEASE_REVOKE_BY_ROOT_SIGNATURE");

        vm.startBroadcast(relayerPk);
        ReleaseRegistry(registry).revokeByRootAuthorized(root, deadline, signature);
        vm.stopBroadcast();
    }
}

