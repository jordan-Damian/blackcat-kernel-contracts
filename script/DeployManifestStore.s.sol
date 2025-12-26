/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {ManifestStore} from "../src/ManifestStore.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Deploy ManifestStore (optional on-chain blob store).
/// @dev Usage:
/// 1) Set env:
///    - `PRIVATE_KEY` (deployer)
///    - `BLACKCAT_MANIFEST_STORE_OWNER` (store owner; typically a Safe)
/// 2) Run:
///    - `forge script script/DeployManifestStore.s.sol:DeployManifestStore --rpc-url <RPC> --broadcast`
contract DeployManifestStore {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (ManifestStore store) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address owner = vm.envAddress("BLACKCAT_MANIFEST_STORE_OWNER");

        vm.startBroadcast(deployerPk);
        store = new ManifestStore(owner);
        vm.stopBroadcast();
    }
}
