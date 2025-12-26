/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

/// @notice Optional on-chain blob store for manifests (paranoid “full detail” mode).
/// @dev Skeleton contract (not audited, not production-ready).
///
/// Design goals:
/// - Append-only, chunked storage keyed by an off-chain content hash (`blobHash`).
/// - Owner-gated writes to prevent third-party sabotage of official blobs.
/// - No on-chain recomputation of the content hash (done off-chain; consumers MUST verify).
contract ManifestStore {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatManifestStore"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant TRANSFER_OWNERSHIP_TYPEHASH =
        keccak256("TransferOwnership(address newOwner,uint256 nonce,uint256 deadline)");
    bytes32 private constant ACCEPT_OWNERSHIP_TYPEHASH =
        keccak256("AcceptOwnership(address newOwner,uint256 nonce,uint256 deadline)");

    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant EIP2098_S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    struct BlobMeta {
        uint64 chunkCount;
        uint64 totalBytes;
        bool finalized;
    }

    address public owner;
    address public pendingOwner;

    /// @dev Increments on each ownership transfer start (direct or authorized); used by accept ownership signatures.
    uint256 public ownershipTransferNonce;

    mapping(bytes32 => BlobMeta) private blobs;
    mapping(bytes32 => mapping(uint64 => bytes)) private chunks;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    event SignatureConsumed(address indexed signer, bytes32 indexed digest, address indexed executor);

    event ChunkAppended(bytes32 indexed blobHash, uint64 indexed index, bytes32 chunkKeccak, uint32 size);
    event BlobFinalized(bytes32 indexed blobHash, uint64 chunkCount, uint64 totalBytes);

    modifier onlyOwner() {
        require(msg.sender == owner, "ManifestStore: not owner");
        _;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "ManifestStore: owner=0");
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ManifestStore: owner=0");
        ownershipTransferNonce += 1;
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function hashTransferOwnership(address newOwner, uint256 deadline) external view returns (bytes32) {
        require(newOwner != address(0), "ManifestStore: owner=0");
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_OWNERSHIP_TYPEHASH, newOwner, ownershipTransferNonce + 1, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function transferOwnershipAuthorized(address newOwner, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "ManifestStore: expired");
        require(newOwner != address(0), "ManifestStore: owner=0");

        uint256 nonce = ownershipTransferNonce + 1;
        bytes32 structHash = keccak256(abi.encode(TRANSFER_OWNERSHIP_TYPEHASH, newOwner, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ManifestStore: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        ownershipTransferNonce = nonce;
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(currentOwner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "ManifestStore: not pending owner");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function hashAcceptOwnership(address expectedNewOwner, uint256 deadline) external view returns (bytes32) {
        address pending = pendingOwner;
        require(pending != address(0), "ManifestStore: no pending owner");
        require(pending == expectedNewOwner, "ManifestStore: pending owner mismatch");

        bytes32 structHash =
            keccak256(abi.encode(ACCEPT_OWNERSHIP_TYPEHASH, expectedNewOwner, ownershipTransferNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function acceptOwnershipAuthorized(address expectedNewOwner, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "ManifestStore: expired");

        address pending = pendingOwner;
        require(pending != address(0), "ManifestStore: no pending owner");
        require(pending == expectedNewOwner, "ManifestStore: pending owner mismatch");

        bytes32 structHash =
            keccak256(abi.encode(ACCEPT_OWNERSHIP_TYPEHASH, expectedNewOwner, ownershipTransferNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        require(_isValidSignatureNow(pending, digest, signature), "ManifestStore: invalid pending owner signature");
        emit SignatureConsumed(pending, digest, msg.sender);

        address previousOwner = owner;
        owner = pending;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function getMeta(bytes32 blobHash) external view returns (uint64 chunkCount, uint64 totalBytes, bool finalized) {
        BlobMeta memory meta = blobs[blobHash];
        return (meta.chunkCount, meta.totalBytes, meta.finalized);
    }

    function getChunk(bytes32 blobHash, uint64 index) external view returns (bytes memory) {
        BlobMeta memory meta = blobs[blobHash];
        require(index < meta.chunkCount, "ManifestStore: index out of range");
        return chunks[blobHash][index];
    }

    function appendChunk(bytes32 blobHash, bytes calldata chunk) external onlyOwner returns (uint64 index) {
        require(blobHash != bytes32(0), "ManifestStore: blobHash=0");
        require(chunk.length != 0, "ManifestStore: empty chunk");
        require(chunk.length <= type(uint32).max, "ManifestStore: chunk too large");

        BlobMeta storage meta = blobs[blobHash];
        require(!meta.finalized, "ManifestStore: finalized");

        index = meta.chunkCount;
        chunks[blobHash][index] = chunk;

        meta.chunkCount = index + 1;
        meta.totalBytes += uint64(chunk.length);

        emit ChunkAppended(blobHash, index, keccak256(chunk), uint32(chunk.length));
    }

    function appendChunks(bytes32 blobHash, bytes[] calldata newChunks) external onlyOwner returns (uint64 startIndex) {
        require(blobHash != bytes32(0), "ManifestStore: blobHash=0");
        uint256 count = newChunks.length;
        require(count != 0, "ManifestStore: empty batch");

        BlobMeta storage meta = blobs[blobHash];
        require(!meta.finalized, "ManifestStore: finalized");

        startIndex = meta.chunkCount;
        uint64 index = startIndex;
        uint64 totalBytes = meta.totalBytes;

        for (uint256 i = 0; i < count; i++) {
            bytes calldata chunk = newChunks[i];
            require(chunk.length != 0, "ManifestStore: empty chunk");
            require(chunk.length <= type(uint32).max, "ManifestStore: chunk too large");

            chunks[blobHash][index] = chunk;
            totalBytes += uint64(chunk.length);
            emit ChunkAppended(blobHash, index, keccak256(chunk), uint32(chunk.length));
            index += 1;
        }

        meta.chunkCount = index;
        meta.totalBytes = totalBytes;
    }

    function finalize(bytes32 blobHash, uint64 expectedChunkCount, uint64 expectedTotalBytes) external onlyOwner {
        require(blobHash != bytes32(0), "ManifestStore: blobHash=0");

        BlobMeta storage meta = blobs[blobHash];
        require(!meta.finalized, "ManifestStore: finalized");
        require(meta.chunkCount != 0, "ManifestStore: empty blob");

        require(meta.chunkCount == expectedChunkCount, "ManifestStore: chunkCount mismatch");
        require(meta.totalBytes == expectedTotalBytes, "ManifestStore: totalBytes mismatch");

        meta.finalized = true;
        emit BlobFinalized(blobHash, meta.chunkCount, meta.totalBytes);
    }

    function _isValidSignatureNow(address signer, bytes32 digest, bytes memory signature) private view returns (bool) {
        if (signer.code.length == 0) {
            return _recover(digest, signature) == signer;
        }

        (bool ok, bytes memory ret) =
            signer.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", digest, signature));
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
            revert("ManifestStore: bad signature length");
        }
        require(v == 27 || v == 28, "ManifestStore: bad v");
        require(uint256(s) <= SECP256K1N_HALF, "ManifestStore: bad s");

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "ManifestStore: bad signature");
        return recovered;
    }
}
