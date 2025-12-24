pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Publish a release into an existing ReleaseRegistry via a relayer (EIP-712 signed by the registry owner).
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (relayer)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_COMPONENT_ID` (bytes32)
///    - `BLACKCAT_RELEASE_VERSION` (uint64 as uint env)
///    - `BLACKCAT_RELEASE_ROOT` (bytes32)
///    - `BLACKCAT_RELEASE_URI_HASH` (bytes32)
///    - `BLACKCAT_RELEASE_META_HASH` (bytes32; optional, set to 0x0 if unused)
///    - `BLACKCAT_RELEASE_PUBLISH_DEADLINE` (uint256; included in signed digest)
///    - `BLACKCAT_RELEASE_PUBLISH_SIGNATURE` (bytes; signature by registry owner, EOA `(r,s,v)`/EIP-2098 or EIP-1271 blob)
/// 2) Run:
///    - `forge script script/PublishReleaseAuthorized.s.sol:PublishReleaseAuthorized --rpc-url <RPC> --broadcast`
contract PublishReleaseAuthorized {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 relayerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");

        bytes32 componentId = vm.envBytes32("BLACKCAT_COMPONENT_ID");
        uint64 version = uint64(vm.envUint("BLACKCAT_RELEASE_VERSION"));
        bytes32 root = vm.envBytes32("BLACKCAT_RELEASE_ROOT");
        bytes32 uriHash = vm.envBytes32("BLACKCAT_RELEASE_URI_HASH");
        bytes32 metaHash = vm.envBytes32("BLACKCAT_RELEASE_META_HASH");

        uint256 deadline = vm.envUint("BLACKCAT_RELEASE_PUBLISH_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_RELEASE_PUBLISH_SIGNATURE");

        vm.startBroadcast(relayerPk);
        ReleaseRegistry(registry).publishAuthorized(componentId, version, root, uriHash, metaHash, deadline, signature);
        vm.stopBroadcast();
    }
}

