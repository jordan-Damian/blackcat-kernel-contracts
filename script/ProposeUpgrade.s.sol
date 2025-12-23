pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Propose an upgrade (raw root + uriHash).
/// @dev Must be executed by `upgradeAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_UPGRADE_ROOT`
/// - `BLACKCAT_UPGRADE_URI_HASH`
/// - `BLACKCAT_UPGRADE_POLICY_HASH`
/// - `BLACKCAT_UPGRADE_TTL_SEC`
contract ProposeUpgrade {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        bytes32 root = vm.envBytes32("BLACKCAT_UPGRADE_ROOT");
        bytes32 uriHash = vm.envBytes32("BLACKCAT_UPGRADE_URI_HASH");
        bytes32 policyHash = vm.envBytes32("BLACKCAT_UPGRADE_POLICY_HASH");
        uint64 ttlSec = uint64(vm.envUint("BLACKCAT_UPGRADE_TTL_SEC"));

        vm.startBroadcast(pk);
        InstanceController(controller).proposeUpgrade(root, uriHash, policyHash, ttlSec);
        vm.stopBroadcast();
    }
}

