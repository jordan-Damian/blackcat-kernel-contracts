pragma solidity ^0.8.24;

import {ManifestStore} from "../src/ManifestStore.sol";
import {FoundryVm} from "./FoundryVm.sol";

/// @notice Upload a manifest/blob into ManifestStore in chunked form.
/// @dev This is intended for the paranoid “full detail” availability mode; it can be very expensive.
///
/// Env:
/// - `PRIVATE_KEY` (must be ManifestStore owner)
/// - `BLACKCAT_MANIFEST_STORE` (address)
/// - `BLACKCAT_BLOB_PATH` (string path; e.g. `./dist/manifest.bin`)
/// - `BLACKCAT_CHUNK_SIZE` (uint, optional; default 24000)
/// - `BLACKCAT_CHUNKS_PER_TX` (uint, optional; default 1; when >1 uses `appendChunks(...)` to reduce tx count)
/// - `BLACKCAT_BLOB_HASH` (bytes32, optional; if set, must match computed sha256(fileBytes))
///
/// Output:
/// - blobHash is `sha256(fileBytes)` (unless `BLACKCAT_BLOB_HASH` is provided and matches).
contract UploadManifestBlob {
    FoundryVm internal constant vm = FoundryVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (bytes32 blobHash) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address store = vm.envAddress("BLACKCAT_MANIFEST_STORE");
        string memory path = vm.envString("BLACKCAT_BLOB_PATH");

        uint256 chunkSize = vm.envOr("BLACKCAT_CHUNK_SIZE", uint256(24000));
        require(chunkSize != 0, "UploadManifestBlob: chunkSize=0");
        uint256 chunksPerTx = vm.envOr("BLACKCAT_CHUNKS_PER_TX", uint256(1));
        require(chunksPerTx != 0, "UploadManifestBlob: chunksPerTx=0");

        bytes memory data = vm.readFileBinary(path);
        require(data.length != 0, "UploadManifestBlob: empty file");

        bytes32 computed = sha256(data);
        bytes32 expected = vm.envOr("BLACKCAT_BLOB_HASH", bytes32(0));
        if (expected != bytes32(0)) {
            require(expected == computed, "UploadManifestBlob: blobHash mismatch");
            blobHash = expected;
        } else {
            blobHash = computed;
        }

        uint256 total = data.length;
        uint64 totalBytes64 = uint64(total);
        require(uint256(totalBytes64) == total, "UploadManifestBlob: file too large");

        uint256 chunksCount = (total + chunkSize - 1) / chunkSize;
        uint64 chunksCount64 = uint64(chunksCount);
        require(uint256(chunksCount64) == chunksCount, "UploadManifestBlob: too many chunks");

        vm.startBroadcast(pk);
        for (uint256 startChunk = 0; startChunk < chunksCount; startChunk += chunksPerTx) {
            uint256 endChunk = startChunk + chunksPerTx;
            if (endChunk > chunksCount) {
                endChunk = chunksCount;
            }

            uint256 batchLen = endChunk - startChunk;
            bytes[] memory batch = new bytes[](batchLen);
            for (uint256 i = 0; i < batchLen; i++) {
                uint256 chunkIndex = startChunk + i;
                uint256 offset = chunkIndex * chunkSize;
                uint256 end = offset + chunkSize;
                if (end > total) {
                    end = total;
                }

                bytes memory chunk = new bytes(end - offset);
                for (uint256 j = 0; j < chunk.length; j++) {
                    chunk[j] = data[offset + j];
                }
                batch[i] = chunk;
            }

            ManifestStore(store).appendChunks(blobHash, batch);
        }

        ManifestStore(store).finalize(blobHash, chunksCount64, totalBytes64);
        vm.stopBroadcast();
    }
}
