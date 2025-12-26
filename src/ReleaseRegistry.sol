/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

/// @notice Global registry of official release roots for the BlackCat ecosystem.
/// @dev Skeleton contract (not audited, not production-ready).
contract ReleaseRegistry {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatReleaseRegistry"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant PUBLISH_TYPEHASH = keccak256(
        "Publish(bytes32 componentId,uint64 version,bytes32 root,bytes32 uriHash,bytes32 metaHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant PUBLISH_BATCH_TYPEHASH =
        keccak256("PublishBatch(bytes32 itemsHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant REVOKE_TYPEHASH =
        keccak256("Revoke(bytes32 componentId,uint64 version,bytes32 root,uint256 nonce,uint256 deadline)");
    bytes32 private constant REVOKE_BATCH_TYPEHASH =
        keccak256("RevokeBatch(bytes32 itemsHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant REVOKE_BY_ROOT_TYPEHASH =
        keccak256("RevokeByRoot(bytes32 root,bytes32 componentId,uint64 version,uint256 nonce,uint256 deadline)");
    bytes32 private constant TRANSFER_OWNERSHIP_TYPEHASH =
        keccak256("TransferOwnership(address newOwner,uint256 nonce,uint256 deadline)");
    bytes32 private constant ACCEPT_OWNERSHIP_TYPEHASH =
        keccak256("AcceptOwnership(address newOwner,uint256 nonce,uint256 deadline)");

    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant EIP2098_S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    struct Release {
        bytes32 root;
        bytes32 uriHash;
        bytes32 metaHash;
    }

    struct RootIndex {
        bytes32 componentId;
        uint64 version;
        bytes32 uriHash;
        bytes32 metaHash;
    }

    struct PublishBatchItem {
        bytes32 componentId;
        uint64 version;
        bytes32 root;
        bytes32 uriHash;
        bytes32 metaHash;
    }

    struct RevokeBatchItem {
        bytes32 componentId;
        uint64 version;
        bytes32 root;
    }

    address public owner;
    address public pendingOwner;

    /// @dev EIP-712 nonce for publish-authorized operations. Increments on any successful publish (direct or authorized).
    uint256 public publishNonce;
    /// @dev EIP-712 nonce for revoke-authorized operations. Increments on any successful revoke (direct or authorized).
    uint256 public revokeNonce;
    /// @dev Increments on each ownership transfer start (direct or authorized); used by accept ownership signatures.
    uint256 public ownershipTransferNonce;

    /// @dev componentId (bytes32) + version (uint64) -> release metadata.
    mapping(bytes32 => mapping(uint64 => Release)) private releases;
    mapping(bytes32 => bool) private publishedRoots;
    mapping(bytes32 => RootIndex) private rootIndex;
    mapping(bytes32 => bool) private revokedRoots;
    mapping(bytes32 => mapping(uint64 => bool)) private revokedReleases;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    event SignatureConsumed(address indexed signer, bytes32 indexed digest, address indexed executor);
    event ReleasePublished(
        bytes32 indexed componentId, uint64 indexed version, bytes32 root, bytes32 uriHash, bytes32 metaHash
    );
    event ReleaseRevoked(bytes32 indexed componentId, uint64 indexed version, bytes32 root);

    modifier onlyOwner() {
        require(msg.sender == owner, "ReleaseRegistry: not owner");
        _;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "ReleaseRegistry: owner=0");
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ReleaseRegistry: owner=0");
        ownershipTransferNonce += 1;
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function hashTransferOwnership(address newOwner, uint256 deadline) external view returns (bytes32) {
        require(newOwner != address(0), "ReleaseRegistry: owner=0");
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_OWNERSHIP_TYPEHASH, newOwner, ownershipTransferNonce + 1, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function transferOwnershipAuthorized(address newOwner, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");
        require(newOwner != address(0), "ReleaseRegistry: owner=0");

        uint256 nonce = ownershipTransferNonce + 1;
        bytes32 structHash = keccak256(abi.encode(TRANSFER_OWNERSHIP_TYPEHASH, newOwner, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        ownershipTransferNonce = nonce;
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(currentOwner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "ReleaseRegistry: not pending owner");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function hashAcceptOwnership(address expectedNewOwner, uint256 deadline) external view returns (bytes32) {
        address pending = pendingOwner;
        require(pending != address(0), "ReleaseRegistry: no pending owner");
        require(pending == expectedNewOwner, "ReleaseRegistry: pending owner mismatch");

        bytes32 structHash =
            keccak256(abi.encode(ACCEPT_OWNERSHIP_TYPEHASH, expectedNewOwner, ownershipTransferNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function acceptOwnershipAuthorized(address expectedNewOwner, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");

        address pending = pendingOwner;
        require(pending != address(0), "ReleaseRegistry: no pending owner");
        require(pending == expectedNewOwner, "ReleaseRegistry: pending owner mismatch");

        bytes32 structHash =
            keccak256(abi.encode(ACCEPT_OWNERSHIP_TYPEHASH, expectedNewOwner, ownershipTransferNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        require(_isValidSignatureNow(pending, digest, signature), "ReleaseRegistry: invalid pending owner signature");
        emit SignatureConsumed(pending, digest, msg.sender);

        address previousOwner = owner;
        owner = pending;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function publish(bytes32 componentId, uint64 version, bytes32 root, bytes32 uriHash, bytes32 metaHash)
        external
        onlyOwner
    {
        _publish(componentId, version, root, uriHash, metaHash);
    }

    function publishBatch(
        bytes32[] calldata componentIds,
        uint64[] calldata versions,
        bytes32[] calldata roots,
        bytes32[] calldata uriHashes,
        bytes32[] calldata metaHashes
    ) external onlyOwner {
        uint256 n = componentIds.length;
        require(
            n == versions.length && n == roots.length && n == uriHashes.length && n == metaHashes.length,
            "ReleaseRegistry: length mismatch"
        );

        for (uint256 i = 0; i < n; i++) {
            _publish(componentIds[i], versions[i], roots[i], uriHashes[i], metaHashes[i]);
        }
    }

    function _publish(bytes32 componentId, uint64 version, bytes32 root, bytes32 uriHash, bytes32 metaHash) private {
        require(componentId != bytes32(0), "ReleaseRegistry: componentId=0");
        require(version != 0, "ReleaseRegistry: version=0");
        require(root != bytes32(0), "ReleaseRegistry: root=0");
        require(!revokedRoots[root], "ReleaseRegistry: root revoked");
        require(rootIndex[root].componentId == bytes32(0), "ReleaseRegistry: root already published");

        require(releases[componentId][version].root == bytes32(0), "ReleaseRegistry: already published");
        releases[componentId][version] = Release({root: root, uriHash: uriHash, metaHash: metaHash});
        publishedRoots[root] = true;
        rootIndex[root] = RootIndex({componentId: componentId, version: version, uriHash: uriHash, metaHash: metaHash});
        publishNonce += 1;
        emit ReleasePublished(componentId, version, root, uriHash, metaHash);
    }

    function hashPublish(
        bytes32 componentId,
        uint64 version,
        bytes32 root,
        bytes32 uriHash,
        bytes32 metaHash,
        uint256 deadline
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(PUBLISH_TYPEHASH, componentId, version, root, uriHash, metaHash, publishNonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function hashPublishBatch(PublishBatchItem[] calldata items, uint256 deadline) external view returns (bytes32) {
        uint256 n = items.length;
        require(n != 0, "ReleaseRegistry: empty batch");

        bytes32 structHash =
            keccak256(abi.encode(PUBLISH_BATCH_TYPEHASH, keccak256(abi.encode(items)), publishNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function publishAuthorized(
        bytes32 componentId,
        uint64 version,
        bytes32 root,
        bytes32 uriHash,
        bytes32 metaHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");

        bytes32 structHash = keccak256(
            abi.encode(PUBLISH_TYPEHASH, componentId, version, root, uriHash, metaHash, publishNonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        _publish(componentId, version, root, uriHash, metaHash);
    }

    function publishBatchAuthorized(PublishBatchItem[] calldata items, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");

        uint256 n = items.length;
        require(n != 0, "ReleaseRegistry: empty batch");

        bytes32 structHash =
            keccak256(abi.encode(PUBLISH_BATCH_TYPEHASH, keccak256(abi.encode(items)), publishNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        for (uint256 i = 0; i < n; i++) {
            PublishBatchItem calldata item = items[i];
            _publish(item.componentId, item.version, item.root, item.uriHash, item.metaHash);
        }
    }

    function revoke(bytes32 componentId, uint64 version) external onlyOwner {
        _revoke(componentId, version);
    }

    function revokeBatch(bytes32[] calldata componentIds, uint64[] calldata versions) external onlyOwner {
        uint256 n = componentIds.length;
        require(n == versions.length, "ReleaseRegistry: length mismatch");

        for (uint256 i = 0; i < n; i++) {
            _revoke(componentIds[i], versions[i]);
        }
    }

    function revokeByRoot(bytes32 root) external onlyOwner {
        require(root != bytes32(0), "ReleaseRegistry: root=0");
        RootIndex memory idx = rootIndex[root];
        require(idx.componentId != bytes32(0), "ReleaseRegistry: root not found");
        _revoke(idx.componentId, idx.version);
    }

    function _revoke(bytes32 componentId, uint64 version) private {
        require(componentId != bytes32(0), "ReleaseRegistry: componentId=0");
        require(version != 0, "ReleaseRegistry: version=0");
        require(!revokedReleases[componentId][version], "ReleaseRegistry: already revoked");

        Release memory rel = releases[componentId][version];
        require(rel.root != bytes32(0), "ReleaseRegistry: release not found");

        revokedReleases[componentId][version] = true;
        revokedRoots[rel.root] = true;
        revokeNonce += 1;
        emit ReleaseRevoked(componentId, version, rel.root);
    }

    function hashRevoke(bytes32 componentId, uint64 version, bytes32 root, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, componentId, version, root, revokeNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function hashRevokeBatch(RevokeBatchItem[] calldata items, uint256 deadline) external view returns (bytes32) {
        uint256 n = items.length;
        require(n != 0, "ReleaseRegistry: empty batch");

        bytes32 structHash =
            keccak256(abi.encode(REVOKE_BATCH_TYPEHASH, keccak256(abi.encode(items)), revokeNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function hashRevokeByRoot(bytes32 root, uint256 deadline) external view returns (bytes32) {
        require(root != bytes32(0), "ReleaseRegistry: root=0");

        RootIndex memory idx = rootIndex[root];
        require(idx.componentId != bytes32(0), "ReleaseRegistry: root not found");

        bytes32 structHash =
            keccak256(abi.encode(REVOKE_BY_ROOT_TYPEHASH, root, idx.componentId, idx.version, revokeNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function revokeAuthorized(
        bytes32 componentId,
        uint64 version,
        bytes32 root,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");
        require(root != bytes32(0), "ReleaseRegistry: root=0");

        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, componentId, version, root, revokeNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        Release memory rel = releases[componentId][version];
        require(rel.root == root, "ReleaseRegistry: root mismatch");
        _revoke(componentId, version);
    }

    function revokeBatchAuthorized(RevokeBatchItem[] calldata items, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");

        uint256 n = items.length;
        require(n != 0, "ReleaseRegistry: empty batch");

        bytes32 structHash =
            keccak256(abi.encode(REVOKE_BATCH_TYPEHASH, keccak256(abi.encode(items)), revokeNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        for (uint256 i = 0; i < n; i++) {
            RevokeBatchItem calldata item = items[i];
            require(item.root != bytes32(0), "ReleaseRegistry: root=0");
            Release memory rel = releases[item.componentId][item.version];
            require(rel.root == item.root, "ReleaseRegistry: root mismatch");
            _revoke(item.componentId, item.version);
        }
    }

    function revokeByRootAuthorized(bytes32 root, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "ReleaseRegistry: expired");
        require(root != bytes32(0), "ReleaseRegistry: root=0");

        RootIndex memory idx = rootIndex[root];
        require(idx.componentId != bytes32(0), "ReleaseRegistry: root not found");

        bytes32 structHash =
            keccak256(abi.encode(REVOKE_BY_ROOT_TYPEHASH, root, idx.componentId, idx.version, revokeNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address currentOwner = owner;
        require(_isValidSignatureNow(currentOwner, digest, signature), "ReleaseRegistry: invalid owner signature");
        emit SignatureConsumed(currentOwner, digest, msg.sender);

        _revoke(idx.componentId, idx.version);
    }

    function get(bytes32 componentId, uint64 version) external view returns (Release memory) {
        return releases[componentId][version];
    }

    function isPublishedRoot(bytes32 root) external view returns (bool) {
        return publishedRoots[root];
    }

    function getByRoot(bytes32 root)
        external
        view
        returns (bytes32 componentId, uint64 version, bytes32 uriHash, bytes32 metaHash, bool revoked)
    {
        RootIndex memory idx = rootIndex[root];
        return (idx.componentId, idx.version, idx.uriHash, idx.metaHash, revokedRoots[root]);
    }

    function isRevokedRoot(bytes32 root) external view returns (bool) {
        return revokedRoots[root];
    }

    function isTrustedRoot(bytes32 root) external view returns (bool) {
        return publishedRoots[root] && !revokedRoots[root];
    }

    function isRevokedRelease(bytes32 componentId, uint64 version) external view returns (bool) {
        return revokedReleases[componentId][version];
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
            revert("ReleaseRegistry: bad signature length");
        }
        require(v == 27 || v == 28, "ReleaseRegistry: bad v");
        require(uint256(s) <= SECP256K1N_HALF, "ReleaseRegistry: bad s");

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "ReleaseRegistry: bad signature");
        return recovered;
    }
}
