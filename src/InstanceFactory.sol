/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {InstanceController} from "./InstanceController.sol";

/// @notice Creates per-install InstanceController contracts.
/// @dev Skeleton factory (not audited, not production-ready). Uses EIP-1167 minimal proxy clones for efficiency.
contract InstanceFactory {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatInstanceFactory"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant SETUP_TYPEHASH = keccak256(
        "SetupRequest(address rootAuthority,address upgradeAuthority,address emergencyAuthority,bytes32 genesisRoot,bytes32 genesisUriHash,bytes32 genesisPolicyHash,bytes32 salt,uint256 deadline)"
    );

    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant EIP2098_S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

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
    event SetupSignatureConsumed(address indexed rootAuthority, bytes32 indexed digest, address indexed relayer);
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

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function hashSetupRequest(
        address rootAuthority,
        address upgradeAuthority,
        address emergencyAuthority,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash,
        bytes32 salt,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                SETUP_TYPEHASH,
                rootAuthority,
                upgradeAuthority,
                emergencyAuthority,
                genesisRoot,
                genesisUriHash,
                genesisPolicyHash,
                salt,
                deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
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
        isInstance[instance] = true;
        InstanceController(instance)
            .initialize(
                rootAuthority,
                upgradeAuthority,
                emergencyAuthority,
                releaseRegistry,
                genesisRoot,
                genesisUriHash,
                genesisPolicyHash
            );

        emit InstanceCreated(instance, rootAuthority, upgradeAuthority, emergencyAuthority, msg.sender);
        return instance;
    }

    /// @notice CREATE2 instance creation, authorized by root authority signature (EOA or EIP-1271 contract).
    /// @dev The signature binds to chainId + factory address via EIP-712 domain separator.
    function createInstanceDeterministicAuthorized(
        address rootAuthority,
        address upgradeAuthority,
        address emergencyAuthority,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash,
        bytes32 salt,
        uint256 deadline,
        bytes calldata rootAuthoritySignature
    ) external returns (address) {
        require(block.timestamp <= deadline, "InstanceFactory: expired");

        bytes32 digest = hashSetupRequest(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            genesisRoot,
            genesisUriHash,
            genesisPolicyHash,
            salt,
            deadline
        );
        require(
            _isValidSignatureNow(rootAuthority, digest, rootAuthoritySignature),
            "InstanceFactory: invalid root signature"
        );
        emit SetupSignatureConsumed(rootAuthority, digest, msg.sender);

        address instance = _cloneDeterministic(implementation, salt);
        isInstance[instance] = true;
        InstanceController(instance)
            .initialize(
                rootAuthority,
                upgradeAuthority,
                emergencyAuthority,
                releaseRegistry,
                genesisRoot,
                genesisUriHash,
                genesisPolicyHash
            );

        emit InstanceCreatedDeterministic(
            instance, salt, rootAuthority, upgradeAuthority, emergencyAuthority, msg.sender
        );
        return instance;
    }

    function predictInstanceAddress(bytes32 salt) external view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                hex"3d602d80600a3d3981f3363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3"
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

    function _isValidSignatureNow(address signer, bytes32 digest, bytes memory signature) private view returns (bool) {
        if (signer.code.length == 0) {
            return _recover(digest, signature) == signer;
        }

        (bool ok, bytes memory ret) =
            signer.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", digest, signature));
        // Casting to `bytes4` is safe because we check `ret.length >= 4` first.
        // forge-lint: disable-next-line(unsafe-typecast)
        return ok && ret.length >= 4 && bytes4(ret) == EIP1271_MAGICVALUE;
    }

    function _recover(bytes32 digest, bytes memory signature) private pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length == 65) {
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }

            if (v < 27) {
                v += 27;
            }
        } else if (signature.length == 64) {
            bytes32 vs;
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }

            s = bytes32(uint256(vs) & EIP2098_S_MASK);
            v = uint8((uint256(vs) >> 255) + 27);
        } else {
            revert("InstanceFactory: bad signature length");
        }
        require(v == 27 || v == 28, "InstanceFactory: bad v");
        require(uint256(s) <= SECP256K1N_HALF, "InstanceFactory: bad s");

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "InstanceFactory: bad signature");
        return recovered;
    }
}
