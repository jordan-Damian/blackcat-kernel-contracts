pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Propose an upgrade by registry `(componentId, version)` (fetches `{root, uriHash}` from the ReleaseRegistry).
/// @dev Must be executed by `upgradeAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_COMPONENT_ID`
/// - `BLACKCAT_RELEASE_VERSION`
/// - `BLACKCAT_UPGRADE_POLICY_HASH`
/// - `BLACKCAT_UPGRADE_TTL_SEC`
contract ProposeUpgradeByRelease {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        bytes32 componentId = vm.envBytes32("BLACKCAT_COMPONENT_ID");
        uint64 version = uint64(vm.envUint("BLACKCAT_RELEASE_VERSION"));
        bytes32 policyHash = vm.envBytes32("BLACKCAT_UPGRADE_POLICY_HASH");
        uint64 ttlSec = uint64(vm.envUint("BLACKCAT_UPGRADE_TTL_SEC"));

        vm.startBroadcast(pk);
        InstanceController(controller).proposeUpgradeByRelease(componentId, version, policyHash, ttlSec);
        vm.stopBroadcast();
    }
}

