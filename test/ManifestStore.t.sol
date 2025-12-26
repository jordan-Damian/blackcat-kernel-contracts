/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ManifestStore} from "../src/ManifestStore.sol";

contract ManifestStoreTest is TestBase {
    address private owner = address(0x1111111111111111111111111111111111111111);
    address private other = address(0x2222222222222222222222222222222222222222);

    function test_constructor_rejects_zero_owner() public {
        vm.expectRevert("ManifestStore: owner=0");
        new ManifestStore(address(0));
    }

    function test_append_and_finalize_and_getChunk() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        uint64 idx0 = store.appendChunk(blob, bytes("hello"));
        assertEq(uint256(idx0), 0, "idx0 mismatch");

        vm.prank(owner);
        uint64 idx1 = store.appendChunk(blob, bytes("world"));
        assertEq(uint256(idx1), 1, "idx1 mismatch");

        (uint64 chunkCount, uint64 totalBytes, bool finalized) = store.getMeta(blob);
        assertEq(uint256(chunkCount), 2, "chunkCount mismatch");
        assertEq(uint256(totalBytes), 10, "totalBytes mismatch");
        assertTrue(!finalized, "should not be finalized");

        vm.prank(owner);
        store.finalize(blob, 2, 10);

        (,, finalized) = store.getMeta(blob);
        assertTrue(finalized, "should be finalized");

        bytes memory c0 = store.getChunk(blob, 0);
        bytes memory c1 = store.getChunk(blob, 1);
        require(keccak256(c0) == keccak256(bytes("hello")), "chunk0 mismatch");
        require(keccak256(c1) == keccak256(bytes("world")), "chunk1 mismatch");
    }

    function test_append_only_owner() public {
        ManifestStore store = new ManifestStore(owner);
        vm.prank(other);
        vm.expectRevert("ManifestStore: not owner");
        store.appendChunk(keccak256("blob"), bytes("x"));
    }

    function test_finalize_only_owner() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        store.appendChunk(blob, bytes("x"));

        vm.prank(other);
        vm.expectRevert("ManifestStore: not owner");
        store.finalize(blob, 1, 1);
    }

    function test_finalize_rejects_mismatch() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        store.appendChunk(blob, bytes("x"));

        vm.prank(owner);
        vm.expectRevert("ManifestStore: chunkCount mismatch");
        store.finalize(blob, 2, 1);

        vm.prank(owner);
        vm.expectRevert("ManifestStore: totalBytes mismatch");
        store.finalize(blob, 1, 2);
    }

    function test_append_rejects_after_finalize() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        store.appendChunk(blob, bytes("x"));

        vm.prank(owner);
        store.finalize(blob, 1, 1);

        vm.prank(owner);
        vm.expectRevert("ManifestStore: finalized");
        store.appendChunk(blob, bytes("y"));
    }

    function test_ownership_transfer_two_step() public {
        ManifestStore store = new ManifestStore(owner);

        vm.prank(owner);
        store.transferOwnership(other);

        vm.prank(other);
        store.acceptOwnership();

        vm.prank(other);
        store.appendChunk(keccak256("blob"), bytes("x"));
    }

    function test_appendChunks_appends_multiple() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        bytes[] memory batch = new bytes[](3);
        batch[0] = bytes("a");
        batch[1] = bytes("bb");
        batch[2] = bytes("ccc");

        vm.prank(owner);
        uint64 startIndex = store.appendChunks(blob, batch);
        assertEq(uint256(startIndex), 0, "startIndex mismatch");

        (uint64 chunkCount, uint64 totalBytes, bool finalized) = store.getMeta(blob);
        assertEq(uint256(chunkCount), 3, "chunkCount mismatch");
        assertEq(uint256(totalBytes), 6, "totalBytes mismatch");
        assertTrue(!finalized, "should not be finalized");

        bytes memory c0 = store.getChunk(blob, 0);
        bytes memory c2 = store.getChunk(blob, 2);
        require(keccak256(c0) == keccak256(bytes("a")), "chunk0 mismatch");
        require(keccak256(c2) == keccak256(bytes("ccc")), "chunk2 mismatch");
    }

    function test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        uint256 newOwnerPk = 0xB0B;
        address newOwnerAddr = vm.addr(newOwnerPk);

        ManifestStore store = new ManifestStore(ownerAddr);

        uint256 deadline1 = block.timestamp + 3600;
        bytes32 digest1 = store.hashTransferOwnership(newOwnerAddr, deadline1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPk, digest1);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);
        store.transferOwnershipAuthorized(newOwnerAddr, deadline1, sig1);

        uint256 deadline2 = block.timestamp + 7200;
        bytes32 digest2 = store.hashAcceptOwnership(newOwnerAddr, deadline2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(newOwnerPk, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        store.acceptOwnershipAuthorized(newOwnerAddr, deadline2, sig2);

        vm.prank(newOwnerAddr);
        store.appendChunk(keccak256("blob"), bytes("x"));
    }
}
