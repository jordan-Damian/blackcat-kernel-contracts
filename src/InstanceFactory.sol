pragma solidity ^0.8.24;

import {InstanceController} from "./InstanceController.sol";

/// @notice Creates per-install InstanceController contracts.
/// @dev Skeleton factory (not audited, not production-ready). Uses EIP-1167 minimal proxy clones for efficiency.
contract InstanceFactory {
    address public immutable implementation;

    event InstanceCreated(
        address indexed instance,
        address indexed rootAuthority,
        address indexed upgradeAuthority,
        address emergencyAuthority
    );

    constructor() {
        implementation = address(new InstanceController());
    }

    function createInstance(
        address rootAuthority,
        address upgradeAuthority,
        address emergencyAuthority,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash
    ) external returns (address) {
        address instance = _clone(implementation);
        InstanceController(instance)
            .initialize(
                rootAuthority, upgradeAuthority, emergencyAuthority, genesisRoot, genesisUriHash, genesisPolicyHash
            );

        emit InstanceCreated(instance, rootAuthority, upgradeAuthority, emergencyAuthority);
        return instance;
    }

    function _clone(address impl) private returns (address instance) {
        // EIP-1167 minimal proxy:
        // 0x3d602d80600a3d3981f3 | 0x363d3d373d3d3d363d73 | <impl> | 0x5af43d82803e903d91602b57fd5bf3
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create(0, ptr, 0x37)
        }
        require(instance != address(0), "InstanceFactory: clone failed");
    }
}
