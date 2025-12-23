pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Set or clear the controller's `expectedComponentId` (ReleaseRegistry component pinning).
/// @dev Must be executed by `rootAuthority` (or an authority contract calling on its behalf).
///
/// Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
/// - `BLACKCAT_EXPECTED_COMPONENT_ID` (use `0x00..00` to clear)
contract SetExpectedComponentId {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");
        bytes32 componentId = vm.envBytes32("BLACKCAT_EXPECTED_COMPONENT_ID");

        vm.startBroadcast(pk);
        InstanceController(controller).setExpectedComponentId(componentId);
        vm.stopBroadcast();
    }
}

