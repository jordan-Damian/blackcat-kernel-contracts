pragma solidity ^0.8.24;

import {InstanceController} from "../src/InstanceController.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Unpause an instance controller (root/emergency authority).
/// @dev Env:
/// - `PRIVATE_KEY`
/// - `BLACKCAT_INSTANCE_CONTROLLER`
contract Unpause {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address controller = vm.envAddress("BLACKCAT_INSTANCE_CONTROLLER");

        vm.startBroadcast(pk);
        InstanceController(controller).unpause();
        vm.stopBroadcast();
    }
}

