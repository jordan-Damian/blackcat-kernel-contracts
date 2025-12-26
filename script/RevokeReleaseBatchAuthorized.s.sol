/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Revoke multiple releases via relayer (EIP-712 signed by the registry owner).
/// @dev Usage:
/// 1) Prepare an ABI-encoded payload file of `ReleaseRegistry.RevokeBatchItem[]` and set:
///    - `BLACKCAT_RELEASE_REVOKE_BATCH_ITEMS_PATH` (string path; e.g. `./tmp/revoke-items.bin`)
/// 2) Set env:
///    - `PRIVATE_KEY` (relayer)
///    - `BLACKCAT_RELEASE_REGISTRY` (address)
///    - `BLACKCAT_RELEASE_REVOKE_BATCH_DEADLINE` (uint256; included in signed digest)
///    - `BLACKCAT_RELEASE_REVOKE_BATCH_SIGNATURE` (bytes; signature by registry owner)
/// 3) Run:
///    - `forge script script/RevokeReleaseBatchAuthorized.s.sol:RevokeReleaseBatchAuthorized --rpc-url <RPC> --broadcast`
contract RevokeReleaseBatchAuthorized {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 relayerPk = vm.envUint("PRIVATE_KEY");
        address registry = vm.envAddress("BLACKCAT_RELEASE_REGISTRY");
        string memory itemsPath = vm.envString("BLACKCAT_RELEASE_REVOKE_BATCH_ITEMS_PATH");

        uint256 deadline = vm.envUint("BLACKCAT_RELEASE_REVOKE_BATCH_DEADLINE");
        bytes memory signature = vm.envBytes("BLACKCAT_RELEASE_REVOKE_BATCH_SIGNATURE");

        bytes memory payload = vm.readFileBinary(itemsPath);
        ReleaseRegistry.RevokeBatchItem[] memory items = abi.decode(payload, (ReleaseRegistry.RevokeBatchItem[]));

        vm.startBroadcast(relayerPk);
        ReleaseRegistry(registry).revokeBatchAuthorized(items, deadline, signature);
        vm.stopBroadcast();
    }
}
