/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract InstanceFactoryTest is TestBase {
    InstanceFactory private factory;

    address private root = address(0x1111111111111111111111111111111111111111);
    address private upgrader = address(0x2222222222222222222222222222222222222222);
    address private emergency = address(0x3333333333333333333333333333333333333333);

    bytes32 private genesisRoot = keccak256("genesis-root");
    bytes32 private genesisUriHash = keccak256("uri");
    bytes32 private genesisPolicyHash = keccak256("policy");

    function setUp() public {
        factory = new InstanceFactory(address(0));
    }

    function test_implementation_is_locked() public {
        InstanceController impl = InstanceController(factory.implementation());
        vm.expectRevert(abi.encodeWithSelector(InstanceController.AlreadyInitialized.selector));
        impl.initialize(root, upgrader, emergency, address(0), genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_constructor_rejects_non_contract_registry() public {
        vm.expectRevert("InstanceFactory: registry not contract");
        new InstanceFactory(address(1));
    }

    function test_createInstance_initializes_clone() public {
        address instance =
            factory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
        assertTrue(instance != address(0), "instance is zero");
        assertTrue(instance != factory.implementation(), "instance must not equal implementation");
        assertTrue(factory.isInstance(instance), "factory must mark instance");

        InstanceController c = InstanceController(instance);
        assertEq(c.rootAuthority(), root, "rootAuthority mismatch");
        assertEq(c.upgradeAuthority(), upgrader, "upgradeAuthority mismatch");
        assertEq(c.emergencyAuthority(), emergency, "emergencyAuthority mismatch");
        assertEq(c.activeRoot(), genesisRoot, "activeRoot mismatch");
        assertEq(c.releaseRegistry(), address(0), "releaseRegistry mismatch");

        // EIP-1167 runtime code is 45 bytes.
        assertEq(instance.code.length, 45, "unexpected clone code length");
    }

    function test_createInstanceDeterministicAuthorized_reverts_on_salt_reuse() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        bytes32 salt = keccak256("salt-2");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        bytes memory sig = _sign(rootPk, digest);

        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );

        vm.expectRevert("InstanceFactory: clone failed");
        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );
    }

    function test_createInstanceDeterministicAuthorized_accepts_eoa_root_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-auth-1");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        address instance = factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );

        assertEq(instance, factory.predictInstanceAddress(salt), "predicted address mismatch");
        assertTrue(factory.isInstance(instance), "factory must mark instance");
        assertEq(instance.code.length, 45, "unexpected clone code length");
    }

    function test_createInstanceDeterministicAuthorized_accepts_compact_eip2098_root_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-auth-1-2098");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        bytes memory sig = toEip2098Signature(v, r, s);

        address instance = factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );

        assertEq(instance, factory.predictInstanceAddress(salt), "predicted address mismatch");
        assertTrue(factory.isInstance(instance), "factory must mark instance");
        assertEq(instance.code.length, 45, "unexpected clone code length");
    }

    function test_createInstanceDeterministicAuthorized_rejects_high_s_malleable_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-auth-high-s");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        uint256 altS = SECP256K1N - uint256(s);
        assertTrue(altS > SECP256K1N_HALF, "signature is not high-s");
        bytes memory sig = toMalleableHighSSignature(v, r, s);

        vm.expectRevert("InstanceFactory: bad s");
        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );
    }

    function test_createInstanceDeterministicAuthorized_accepts_kernelAuthority_root_signature() public {
        uint256 pk1 = 0xA11CE;
        uint256 pk2 = 0xB0B;
        address a1 = vm.addr(pk1);
        address a2 = vm.addr(pk2);

        address[] memory signers = new address[](2);
        if (a1 < a2) {
            signers[0] = a1;
            signers[1] = a2;
        } else {
            signers[0] = a2;
            signers[1] = a1;
        }

        KernelAuthority rootAuth = new KernelAuthority(signers, 2);

        bytes32 salt = keccak256("salt-auth-2");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            address(rootAuth), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );

        bytes[] memory sigs = new bytes[](2);
        if (a1 < a2) {
            sigs[0] = _sign(pk1, digest);
            sigs[1] = _sign(pk2, digest);
        } else {
            sigs[0] = _sign(pk2, digest);
            sigs[1] = _sign(pk1, digest);
        }

        bytes memory packed = abi.encode(sigs);

        address instance = factory.createInstanceDeterministicAuthorized(
            address(rootAuth),
            upgrader,
            emergency,
            genesisRoot,
            genesisUriHash,
            genesisPolicyHash,
            salt,
            deadline,
            packed
        );

        assertEq(instance, factory.predictInstanceAddress(salt), "predicted address mismatch");
        assertTrue(factory.isInstance(instance), "factory must mark instance");
    }

    function test_createInstanceDeterministicAuthorized_rejects_expired() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-auth-expired");
        uint256 deadline = 0;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("InstanceFactory: expired");
        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );
    }

    function test_createInstanceDeterministicAuthorized_rejects_wrong_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-auth-wrong-sig");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("InstanceFactory: invalid root signature");
        factory.createInstanceDeterministicAuthorized(
            root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, sig
        );
    }

    function test_createInstance_reverts_on_invalid_args() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroRootAuthority.selector));
        factory.createInstance(address(0), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
