pragma solidity ^0.8.24;

/// @notice Global registry of official release roots for the BlackCat ecosystem.
/// @dev Skeleton contract (not audited, not production-ready).
contract ReleaseRegistry {
    struct Release {
        bytes32 root;
        bytes32 uriHash;
        bytes32 metaHash;
    }

    address public owner;
    address public pendingOwner;

    /// @dev componentId (bytes32) + version (uint64) -> release metadata.
    mapping(bytes32 => mapping(uint64 => Release)) private releases;
    mapping(bytes32 => bool) private publishedRoots;
    mapping(bytes32 => bool) private revokedRoots;
    mapping(bytes32 => mapping(uint64 => bool)) private revokedReleases;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
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

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ReleaseRegistry: owner=0");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "ReleaseRegistry: not pending owner");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function publish(bytes32 componentId, uint64 version, bytes32 root, bytes32 uriHash, bytes32 metaHash)
        external
        onlyOwner
    {
        require(componentId != bytes32(0), "ReleaseRegistry: componentId=0");
        require(version != 0, "ReleaseRegistry: version=0");
        require(root != bytes32(0), "ReleaseRegistry: root=0");
        require(!revokedRoots[root], "ReleaseRegistry: root revoked");

        require(releases[componentId][version].root == bytes32(0), "ReleaseRegistry: already published");
        releases[componentId][version] = Release({root: root, uriHash: uriHash, metaHash: metaHash});
        publishedRoots[root] = true;
        emit ReleasePublished(componentId, version, root, uriHash, metaHash);
    }

    function revoke(bytes32 componentId, uint64 version) external onlyOwner {
        require(componentId != bytes32(0), "ReleaseRegistry: componentId=0");
        require(version != 0, "ReleaseRegistry: version=0");
        require(!revokedReleases[componentId][version], "ReleaseRegistry: already revoked");

        Release memory rel = releases[componentId][version];
        require(rel.root != bytes32(0), "ReleaseRegistry: release not found");

        revokedReleases[componentId][version] = true;
        revokedRoots[rel.root] = true;
        emit ReleaseRevoked(componentId, version, rel.root);
    }

    function get(bytes32 componentId, uint64 version) external view returns (Release memory) {
        return releases[componentId][version];
    }

    function isPublishedRoot(bytes32 root) external view returns (bool) {
        return publishedRoots[root];
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
}
