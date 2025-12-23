pragma solidity ^0.8.24;

import {InstanceController} from "./InstanceController.sol";

/// @notice Creates per-install InstanceController contracts.
/// @dev Skeleton factory (not audited, not production-ready). Uses EIP-1167 minimal proxy clones for efficiency.
contract InstanceFactory {
    address public immutable implementation;
    address public immutable releaseRegistry;
    mapping(address => bool) public isInstance;

    event InstanceCreated(
        address indexed instance,
        address indexed rootAuthority,
        address indexed upgradeAuthority,
        address emergencyAuthority,
        address createdBy
    );
    event InstanceCreatedDeterministic(
        address indexed instance,
        bytes32 indexed salt,
        address indexed rootAuthority,
        address upgradeAuthority,
        address emergencyAuthority,
        address createdBy
    );

    constructor(address releaseRegistry_) {
        if (releaseRegistry_ != address(0)) {
            require(releaseRegistry_.code.length != 0, "InstanceFactory: registry not contract");
        }
        implementation = address(new InstanceController());
        releaseRegistry = releaseRegistry_;
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
        InstanceController(instance).initialize(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            releaseRegistry,
            genesisRoot,
            genesisUriHash,
            genesisPolicyHash
        );

        isInstance[instance] = true;
        emit InstanceCreated(instance, rootAuthority, upgradeAuthority, emergencyAuthority, msg.sender);
        return instance;
    }

    function createInstanceDeterministic(
        address rootAuthority,
        address upgradeAuthority,
        address emergencyAuthority,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash,
        bytes32 salt
    ) external returns (address) {
        address instance = _cloneDeterministic(implementation, salt);
        InstanceController(instance).initialize(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            releaseRegistry,
            genesisRoot,
            genesisUriHash,
            genesisPolicyHash
        );

        isInstance[instance] = true;
        emit InstanceCreatedDeterministic(
            instance, salt, rootAuthority, upgradeAuthority, emergencyAuthority, msg.sender
        );
        return instance;
    }

    function predictInstanceAddress(bytes32 salt) external view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
                implementation,
                hex"5af43d82803e903d91602b57fd5bf3"
            )
        );

        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash));
        return address(uint160(uint256(h)));
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

    function _cloneDeterministic(address impl, bytes32 salt) private returns (address instance) {
        // EIP-1167 minimal proxy (CREATE2): see `_clone` for bytecode layout.
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create2(0, ptr, 0x37, salt)
        }
        require(instance != address(0), "InstanceFactory: clone failed");
    }
}
