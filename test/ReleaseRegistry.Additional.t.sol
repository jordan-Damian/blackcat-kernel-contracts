/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";

contract ReleaseRegistryAdditionalTest is TestBase {
    function test_publishBatch_rejects_length_mismatch() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));

        bytes32[] memory components = new bytes32[](2);
        uint64[] memory versions = new uint64[](1);
        bytes32[] memory roots = new bytes32[](2);
        bytes32[] memory uriHashes = new bytes32[](2);
        bytes32[] memory metaHashes = new bytes32[](2);

        components[0] = keccak256("c1");
        components[1] = keccak256("c2");
        versions[0] = 1;
        roots[0] = keccak256("r1");
        roots[1] = keccak256("r2");
        uriHashes[0] = keccak256("u1");
        uriHashes[1] = keccak256("u2");
        metaHashes[0] = keccak256("m1");
        metaHashes[1] = keccak256("m2");

        vm.expectRevert("ReleaseRegistry: length mismatch");
        registry.publishBatch(components, versions, roots, uriHashes, metaHashes);
    }

    function test_revokeBatch_rejects_length_mismatch() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));

        bytes32[] memory components = new bytes32[](2);
        uint64[] memory versions = new uint64[](1);
        components[0] = keccak256("c1");
        components[1] = keccak256("c2");
        versions[0] = 1;

        vm.expectRevert("ReleaseRegistry: length mismatch");
        registry.revokeBatch(components, versions);
    }

    function test_revoke_rejects_release_not_found() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        vm.expectRevert("ReleaseRegistry: release not found");
        registry.revoke(keccak256("c"), 1);
    }

    function test_revoke_rejects_already_revoked() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("c");
        uint64 version = 1;
        bytes32 root = keccak256("r");

        registry.publish(component, version, root, 0, 0);
        registry.revoke(component, version);

        vm.expectRevert("ReleaseRegistry: already revoked");
        registry.revoke(component, version);
    }

    function test_revokeByRoot_rejects_zero_root() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        vm.expectRevert("ReleaseRegistry: root=0");
        registry.revokeByRoot(bytes32(0));
    }

    function test_revokeByRoot_rejects_root_not_found() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        vm.expectRevert("ReleaseRegistry: root not found");
        registry.revokeByRoot(keccak256("unknown"));
    }

    function test_hashAcceptOwnership_rejects_without_pending_owner() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        vm.expectRevert("ReleaseRegistry: no pending owner");
        registry.hashAcceptOwnership(address(0x1234), block.timestamp + 3600);
    }

    function test_transferOwnershipAuthorized_rejects_expired() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        uint256 deadline = block.timestamp + 1;
        bytes32 digest = registry.hashTransferOwnership(address(0x1234), deadline);
        bytes memory sig = _sign(ownerPk, digest);

        vm.warp(deadline + 1);
        vm.expectRevert("ReleaseRegistry: expired");
        registry.transferOwnershipAuthorized(address(0x1234), deadline, sig);
    }

    function test_transferOwnershipAuthorized_rejects_invalid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashTransferOwnership(address(0x1234), deadline);
        bytes memory sig = _sign(0xB0B, digest);

        vm.expectRevert("ReleaseRegistry: invalid owner signature");
        registry.transferOwnershipAuthorized(address(0x1234), deadline, sig);
    }

    function test_acceptOwnershipAuthorized_rejects_invalid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        uint256 newOwnerPk = 0xB0B;
        address newOwnerAddr = vm.addr(newOwnerPk);

        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        uint256 deadline1 = block.timestamp + 3600;
        bytes32 digest1 = registry.hashTransferOwnership(newOwnerAddr, deadline1);
        bytes memory sig1 = _sign(ownerPk, digest1);
        registry.transferOwnershipAuthorized(newOwnerAddr, deadline1, sig1);

        uint256 deadline2 = block.timestamp + 7200;
        bytes32 digest2 = registry.hashAcceptOwnership(newOwnerAddr, deadline2);
        bytes memory sig2 = _sign(0xC0DE, digest2);

        vm.expectRevert("ReleaseRegistry: invalid pending owner signature");
        registry.acceptOwnershipAuthorized(newOwnerAddr, deadline2, sig2);
    }

    function test_revokeAuthorized_rejects_root_mismatch_even_with_valid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("c");
        uint64 version = 1;
        bytes32 root = keccak256("root");
        bytes32 wrongRoot = keccak256("wrong-root");

        vm.prank(ownerAddr);
        registry.publish(component, version, root, 0, 0);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevoke(component, version, wrongRoot, deadline);
        bytes memory sig = _sign(ownerPk, digest);

        vm.expectRevert("ReleaseRegistry: root mismatch");
        registry.revokeAuthorized(component, version, wrongRoot, deadline, sig);
    }

    function test_revokeAuthorized_rejects_invalid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("c");
        uint64 version = 1;
        bytes32 root = keccak256("root");

        vm.prank(ownerAddr);
        registry.publish(component, version, root, 0, 0);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevoke(component, version, root, deadline);
        bytes memory sig = _sign(0xB0B, digest);

        vm.expectRevert("ReleaseRegistry: invalid owner signature");
        registry.revokeAuthorized(component, version, root, deadline, sig);
    }

    function test_revokeBatchAuthorized_rejects_root_mismatch() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("c");
        uint64 version = 1;
        bytes32 root = keccak256("root");

        vm.prank(ownerAddr);
        registry.publish(component, version, root, 0, 0);

        ReleaseRegistry.RevokeBatchItem[] memory items = new ReleaseRegistry.RevokeBatchItem[](1);
        items[0] = ReleaseRegistry.RevokeBatchItem({componentId: component, version: version, root: keccak256("x")});

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevokeBatch(items, deadline);
        bytes memory sig = _sign(ownerPk, digest);

        vm.expectRevert("ReleaseRegistry: root mismatch");
        registry.revokeBatchAuthorized(items, deadline, sig);
    }

    function test_revokeByRootAuthorized_rejects_root_not_found() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        vm.expectRevert("ReleaseRegistry: root not found");
        registry.revokeByRootAuthorized(keccak256("unknown"), block.timestamp + 3600, "");
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}

