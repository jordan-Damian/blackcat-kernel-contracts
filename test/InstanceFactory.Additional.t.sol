/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract InstanceFactoryAdditionalTest is TestBase {
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

    function test_createInstance_rejects_zero_upgrade_authority() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroUpgradeAuthority.selector));
        factory.createInstance(root, address(0), emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_createInstance_rejects_zero_emergency_authority() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroEmergencyAuthority.selector));
        factory.createInstance(root, upgrader, address(0), genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_createInstance_rejects_zero_genesis_root() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroGenesisRoot.selector));
        factory.createInstance(root, upgrader, emergency, bytes32(0), genesisUriHash, genesisPolicyHash);
    }

    function test_createInstanceDeterministicAuthorized_rejects_bad_signature_length_for_eoa_root() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-bad-siglen");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );

        bytes memory badSig = bytes("x");

        vm.expectRevert("InstanceFactory: bad signature length");
        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, badSig
        );

        // Sanity: digest is computed (no-op) to ensure we didn't use an uninitialized value.
        assertTrue(digest != bytes32(0), "digest must not be zero");
    }

    function test_createInstanceDeterministicAuthorized_rejects_bad_v_for_eoa_root() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        bytes32 salt = keccak256("salt-bad-v");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        // Produce an invalid v (do not trigger the v<27 normalization).
        uint8 badV = v == 27 ? 29 : 30;
        bytes memory badSig = abi.encodePacked(r, s, badV);

        vm.expectRevert("InstanceFactory: bad v");
        factory.createInstanceDeterministicAuthorized(
            rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline, badSig
        );
    }

    function test_createInstanceDeterministicAuthorized_rejects_invalid_kernelAuthority_signature() public {
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

        bytes32 salt = keccak256("salt-invalid-ka");
        uint256 deadline = block.timestamp + 3600;

        bytes32 digest = factory.hashSetupRequest(
            address(rootAuth), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash, salt, deadline
        );

        // KernelAuthority requires 2 signatures, but we only provide 1.
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(pk1, digest);
        bytes memory packed = abi.encode(sigs);

        vm.expectRevert("InstanceFactory: invalid root signature");
        factory.createInstanceDeterministicAuthorized(
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
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}

