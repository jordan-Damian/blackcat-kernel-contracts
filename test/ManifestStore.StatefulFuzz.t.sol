/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ManifestStore} from "../src/ManifestStore.sol";

/// @notice Lightweight “stateful fuzz” tests without external dependencies.
/// @dev We intentionally ignore reverts for random operations and assert invariants after each step.
contract ManifestStoreStatefulFuzzTest is TestBase {
    function testFuzz_stateful_blob_invariants(uint256 seed) public {
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address other = address(0xB0B);

        ManifestStore store = new ManifestStore(owner);

        bytes32 blobHash = keccak256(abi.encodePacked("blob", seed));
        vm.assume(blobHash != bytes32(0));

        uint256 steps = (seed % 16) + 1;

        uint64 expectedChunkCount = 0;
        uint64 expectedTotalBytes = 0;
        bool expectedFinalized = false;

        uint256 maxChunks = steps * 2 + 2;
        bytes32[] memory expectedChunkKeccak = new bytes32[](maxChunks);
        uint32[] memory expectedChunkSize = new uint32[](maxChunks);

        for (uint256 i = 0; i < steps; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint8 op = uint8(seed % 6);

            if (op == 0) {
                bytes memory chunk = _chunkFromSeed(seed, i);
                (bool ok, bytes memory ret) =
                    _tryAs(owner, address(store), abi.encodeCall(ManifestStore.appendChunk, (blobHash, chunk)));
                if (ok) {
                    uint64 index = abi.decode(ret, (uint64));
                    assertEq(uint256(index), uint256(expectedChunkCount), "appendChunk index mismatch");

                    expectedChunkKeccak[index] = keccak256(chunk);
                    expectedChunkSize[index] = uint32(chunk.length);
                    expectedChunkCount += 1;
                    expectedTotalBytes += uint64(chunk.length);
                } else {
                    assertTrue(expectedFinalized, "appendChunk should only fail after finalize");
                }
            } else if (op == 1) {
                bytes[] memory chunks_ = new bytes[](2);
                chunks_[0] = _chunkFromSeed(seed, i);
                chunks_[1] = _chunkFromSeed(uint256(keccak256(abi.encode(seed, "b"))), i + 1);

                (bool ok, bytes memory ret) =
                    _tryAs(owner, address(store), abi.encodeCall(ManifestStore.appendChunks, (blobHash, chunks_)));
                if (ok) {
                    uint64 startIndex = abi.decode(ret, (uint64));
                    assertEq(uint256(startIndex), uint256(expectedChunkCount), "appendChunks startIndex mismatch");

                    for (uint256 j = 0; j < chunks_.length; j++) {
                        uint64 index = uint64(uint256(startIndex) + j);
                        expectedChunkKeccak[index] = keccak256(chunks_[j]);
                        expectedChunkSize[index] = uint32(chunks_[j].length);
                        expectedChunkCount += 1;
                        expectedTotalBytes += uint64(chunks_[j].length);
                    }
                } else {
                    assertTrue(expectedFinalized, "appendChunks should only fail after finalize");
                }
            } else if (op == 2) {
                bool useCorrect = (seed & 1) == 1;
                uint64 expCount = useCorrect ? expectedChunkCount : expectedChunkCount + 1;
                uint64 expBytes = useCorrect ? expectedTotalBytes : expectedTotalBytes + 1;

                (bool ok,) = _tryAs(
                    owner, address(store), abi.encodeCall(ManifestStore.finalize, (blobHash, expCount, expBytes))
                );
                if (ok) {
                    assertTrue(useCorrect, "finalize must not succeed with wrong expected values");
                    assertTrue(!expectedFinalized, "finalize must not succeed twice");
                    assertTrue(expectedChunkCount != 0, "finalize must not succeed on empty blob");
                    expectedFinalized = true;
                }
            } else if (op == 3) {
                (, bytes memory metaRet) = _call(address(store), abi.encodeCall(ManifestStore.getMeta, (blobHash)));
                (uint64 count_, uint64 bytes_, bool finalized_) = abi.decode(metaRet, (uint64, uint64, bool));
                assertEq(uint256(count_), uint256(expectedChunkCount), "getMeta chunkCount mismatch");
                assertEq(uint256(bytes_), uint256(expectedTotalBytes), "getMeta totalBytes mismatch");
                assertTrue(finalized_ == expectedFinalized, "getMeta finalized mismatch");
            } else if (op == 4) {
                // Not-owner must not be able to mutate state.
                bytes memory chunk = _chunkFromSeed(seed, i);
                (bool ok,) = _tryAs(other, address(store), abi.encodeCall(ManifestStore.appendChunk, (blobHash, chunk)));
                assertTrue(!ok, "appendChunk must reject non-owner");
            } else {
                // Once finalized, writes must fail (defense in depth).
                if (expectedFinalized) {
                    bytes memory chunk = _chunkFromSeed(seed, i);
                    (bool ok1,) =
                        _tryAs(owner, address(store), abi.encodeCall(ManifestStore.appendChunk, (blobHash, chunk)));
                    assertTrue(!ok1, "appendChunk must reject after finalize");

                    bytes[] memory chunks_ = new bytes[](1);
                    chunks_[0] = chunk;
                    (bool ok2,) =
                        _tryAs(owner, address(store), abi.encodeCall(ManifestStore.appendChunks, (blobHash, chunks_)));
                    assertTrue(!ok2, "appendChunks must reject after finalize");
                }
            }

            // Invariant: getMeta always matches our tracked expectation.
            (, bytes memory metaRet2) = _call(address(store), abi.encodeCall(ManifestStore.getMeta, (blobHash)));
            (uint64 count2, uint64 totalBytes2, bool finalized2) = abi.decode(metaRet2, (uint64, uint64, bool));
            assertEq(uint256(count2), uint256(expectedChunkCount), "meta chunkCount drift");
            assertEq(uint256(totalBytes2), uint256(expectedTotalBytes), "meta totalBytes drift");
            assertTrue(finalized2 == expectedFinalized, "meta finalized drift");

            // Invariant: index == chunkCount is always out of range.
            (bool outOk,) = _call(address(store), abi.encodeCall(ManifestStore.getChunk, (blobHash, count2)));
            assertTrue(!outOk, "getChunk must revert for index==chunkCount");

            // Invariant: if there are chunks, a random in-range index must be retrievable and match.
            if (count2 != 0) {
                uint64 idx = uint64(seed % uint256(count2));
                (bool inOk, bytes memory chunkRet) =
                    _call(address(store), abi.encodeCall(ManifestStore.getChunk, (blobHash, idx)));
                assertTrue(inOk, "getChunk must succeed for in-range index");

                bytes memory chunkBytes = abi.decode(chunkRet, (bytes));
                assertTrue(chunkBytes.length != 0, "stored chunk must not be empty");
                assertEq(keccak256(chunkBytes), expectedChunkKeccak[idx], "stored chunk keccak mismatch");
                assertEq(uint256(chunkBytes.length), uint256(expectedChunkSize[idx]), "stored chunk size mismatch");
            }
        }
    }

    function _chunkFromSeed(uint256 seed, uint256 salt) private pure returns (bytes memory) {
        // Keep chunks small to keep fuzz runs fast and deterministic.
        uint8 len = uint8((uint256(keccak256(abi.encode(seed, salt))) % 32) + 1);
        bytes memory out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, salt, i))) % 256));
        }
        return out;
    }

    function _tryAs(address sender, address target, bytes memory data) private returns (bool ok, bytes memory ret) {
        vm.prank(sender);
        (ok, ret) = target.call(data);
    }

    function _call(address target, bytes memory data) private returns (bool ok, bytes memory ret) {
        (ok, ret) = target.call(data);
    }
}
