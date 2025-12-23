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

    /// @dev componentId (bytes32) + version (uint64) -> release metadata.
    mapping(bytes32 => mapping(uint64 => Release)) private releases;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ReleasePublished(bytes32 indexed componentId, uint64 indexed version, bytes32 root, bytes32 uriHash, bytes32 metaHash);

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
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    function publish(bytes32 componentId, uint64 version, bytes32 root, bytes32 uriHash, bytes32 metaHash) external onlyOwner {
        require(componentId != bytes32(0), "ReleaseRegistry: componentId=0");
        require(version != 0, "ReleaseRegistry: version=0");
        require(root != bytes32(0), "ReleaseRegistry: root=0");

        releases[componentId][version] = Release({root: root, uriHash: uriHash, metaHash: metaHash});
        emit ReleasePublished(componentId, version, root, uriHash, metaHash);
    }

    function get(bytes32 componentId, uint64 version) external view returns (Release memory) {
        return releases[componentId][version];
    }
}

