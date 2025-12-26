/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ManifestStore} from "../src/ManifestStore.sol";

contract ManifestStoreAdditionalTest is TestBase {
    address private owner = address(0x1111111111111111111111111111111111111111);
    address private other = address(0x2222222222222222222222222222222222222222);

    function test_getChunk_reverts_out_of_range() public {
        ManifestStore store = new ManifestStore(owner);
        vm.expectRevert("ManifestStore: index out of range");
        store.getChunk(keccak256("blob"), 0);
    }

    function test_appendChunk_rejects_blobHash_zero() public {
        ManifestStore store = new ManifestStore(owner);
        vm.prank(owner);
        vm.expectRevert("ManifestStore: blobHash=0");
        store.appendChunk(bytes32(0), bytes("x"));
    }

    function test_appendChunk_rejects_empty_chunk() public {
        ManifestStore store = new ManifestStore(owner);
        vm.prank(owner);
        vm.expectRevert("ManifestStore: empty chunk");
        store.appendChunk(keccak256("blob"), bytes(""));
    }

    function test_appendChunks_rejects_empty_batch() public {
        ManifestStore store = new ManifestStore(owner);
        bytes[] memory batch = new bytes[](0);

        vm.prank(owner);
        vm.expectRevert("ManifestStore: empty batch");
        store.appendChunks(keccak256("blob"), batch);
    }

    function test_appendChunks_rejects_empty_chunk() public {
        ManifestStore store = new ManifestStore(owner);
        bytes[] memory batch = new bytes[](2);
        batch[0] = bytes("a");
        batch[1] = bytes("");

        vm.prank(owner);
        vm.expectRevert("ManifestStore: empty chunk");
        store.appendChunks(keccak256("blob"), batch);
    }

    function test_finalize_rejects_blobHash_zero() public {
        ManifestStore store = new ManifestStore(owner);

        vm.prank(owner);
        vm.expectRevert("ManifestStore: blobHash=0");
        store.finalize(bytes32(0), 0, 0);
    }

    function test_finalize_rejects_empty_blob() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        vm.expectRevert("ManifestStore: empty blob");
        store.finalize(blob, 0, 0);
    }

    function test_finalize_rejects_already_finalized() public {
        ManifestStore store = new ManifestStore(owner);
        bytes32 blob = keccak256("blob");

        vm.prank(owner);
        store.appendChunk(blob, bytes("x"));

        vm.prank(owner);
        store.finalize(blob, 1, 1);

        vm.prank(owner);
        vm.expectRevert("ManifestStore: finalized");
        store.finalize(blob, 1, 1);
    }

    function test_hashAcceptOwnership_rejects_without_pending_owner() public {
        ManifestStore store = new ManifestStore(owner);
        vm.expectRevert("ManifestStore: no pending owner");
        store.hashAcceptOwnership(other, block.timestamp + 3600);
    }

    function test_transferOwnershipAuthorized_rejects_expired() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ManifestStore store = new ManifestStore(ownerAddr);

        uint256 deadline = block.timestamp + 1;
        bytes32 digest = store.hashTransferOwnership(other, deadline);
        bytes memory sig = _sign(ownerPk, digest);

        vm.warp(deadline + 1);
        vm.expectRevert("ManifestStore: expired");
        store.transferOwnershipAuthorized(other, deadline, sig);
    }

    function test_transferOwnershipAuthorized_rejects_invalid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ManifestStore store = new ManifestStore(ownerAddr);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = store.hashTransferOwnership(other, deadline);
        bytes memory sig = _sign(0xB0B, digest);

        vm.expectRevert("ManifestStore: invalid owner signature");
        store.transferOwnershipAuthorized(other, deadline, sig);
    }

    function test_acceptOwnershipAuthorized_rejects_pending_owner_mismatch() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        uint256 newOwnerPk = 0xB0B;
        address newOwnerAddr = vm.addr(newOwnerPk);

        ManifestStore store = new ManifestStore(ownerAddr);

        uint256 deadline1 = block.timestamp + 3600;
        bytes32 digest1 = store.hashTransferOwnership(newOwnerAddr, deadline1);
        bytes memory sig1 = _sign(ownerPk, digest1);
        store.transferOwnershipAuthorized(newOwnerAddr, deadline1, sig1);

        uint256 deadline2 = block.timestamp + 7200;
        vm.expectRevert("ManifestStore: pending owner mismatch");
        store.hashAcceptOwnership(other, deadline2);

        bytes32 digest2 = store.hashAcceptOwnership(newOwnerAddr, deadline2);
        bytes memory sig2 = _sign(newOwnerPk, digest2);

        vm.expectRevert("ManifestStore: pending owner mismatch");
        store.acceptOwnershipAuthorized(other, deadline2, sig2);
    }

    function test_acceptOwnershipAuthorized_rejects_invalid_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        uint256 newOwnerPk = 0xB0B;
        address newOwnerAddr = vm.addr(newOwnerPk);

        ManifestStore store = new ManifestStore(ownerAddr);

        uint256 deadline1 = block.timestamp + 3600;
        bytes32 digest1 = store.hashTransferOwnership(newOwnerAddr, deadline1);
        bytes memory sig1 = _sign(ownerPk, digest1);
        store.transferOwnershipAuthorized(newOwnerAddr, deadline1, sig1);

        uint256 deadline2 = block.timestamp + 7200;
        bytes32 digest2 = store.hashAcceptOwnership(newOwnerAddr, deadline2);
        bytes memory sig2 = _sign(0xC0DE, digest2);

        vm.expectRevert("ManifestStore: invalid pending owner signature");
        store.acceptOwnershipAuthorized(newOwnerAddr, deadline2, sig2);
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}

