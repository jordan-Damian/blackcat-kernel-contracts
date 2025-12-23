pragma solidity ^0.8.24;

/// @notice Per-install trust authority for a single BlackCat deployment.
/// @dev Skeleton contract (not audited, not production-ready).
contract InstanceController {
    struct UpgradeProposal {
        bytes32 root;
        bytes32 uriHash;
        bytes32 policyHash;
        uint64 createdAt;
        uint64 ttlSec;
    }

    address public rootAuthority;
    address public upgradeAuthority;
    address public emergencyAuthority;

    bool public paused;

    bytes32 public activeRoot;
    bytes32 public activeUriHash;
    bytes32 public activePolicyHash;

    UpgradeProposal public pendingUpgrade;

    event Initialized(address indexed rootAuthority, address indexed upgradeAuthority, address indexed emergencyAuthority);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event UpgradeProposed(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec);
    event UpgradeActivated(bytes32 root, bytes32 uriHash, bytes32 policyHash);
    event RootAuthorityChanged(address indexed previousValue, address indexed newValue);
    event UpgradeAuthorityChanged(address indexed previousValue, address indexed newValue);
    event EmergencyAuthorityChanged(address indexed previousValue, address indexed newValue);

    modifier onlyRootAuthority() {
        require(msg.sender == rootAuthority, "InstanceController: not root authority");
        _;
    }

    modifier onlyUpgradeAuthority() {
        require(msg.sender == upgradeAuthority, "InstanceController: not upgrade authority");
        _;
    }

    modifier onlyEmergencyAuthority() {
        require(msg.sender == emergencyAuthority, "InstanceController: not emergency authority");
        _;
    }

    /// @dev Lock the implementation instance (clones do not execute constructors).
    constructor() {
        rootAuthority = address(1);
    }

    /// @dev This initializer is intended for clones (EIP-1167).
    function initialize(
        address rootAuthority_,
        address upgradeAuthority_,
        address emergencyAuthority_,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash
    ) external {
        require(rootAuthority == address(0), "InstanceController: already initialized");
        require(rootAuthority_ != address(0), "InstanceController: root=0");
        require(upgradeAuthority_ != address(0), "InstanceController: upgrade=0");
        require(emergencyAuthority_ != address(0), "InstanceController: emergency=0");
        require(genesisRoot != bytes32(0), "InstanceController: genesisRoot=0");

        rootAuthority = rootAuthority_;
        upgradeAuthority = upgradeAuthority_;
        emergencyAuthority = emergencyAuthority_;

        activeRoot = genesisRoot;
        activeUriHash = genesisUriHash;
        activePolicyHash = genesisPolicyHash;

        emit Initialized(rootAuthority_, upgradeAuthority_, emergencyAuthority_);
        emit UpgradeActivated(genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function pause() external onlyEmergencyAuthority {
        if (!paused) {
            paused = true;
            emit Paused(msg.sender);
        }
    }

    function unpause() external onlyEmergencyAuthority {
        if (paused) {
            paused = false;
            emit Unpaused(msg.sender);
        }
    }

    function setRootAuthority(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: root=0");
        address previousValue = rootAuthority;
        rootAuthority = newValue;
        emit RootAuthorityChanged(previousValue, newValue);
    }

    function setUpgradeAuthority(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: upgrade=0");
        address previousValue = upgradeAuthority;
        upgradeAuthority = newValue;
        emit UpgradeAuthorityChanged(previousValue, newValue);
    }

    function setEmergencyAuthority(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: emergency=0");
        address previousValue = emergencyAuthority;
        emergencyAuthority = newValue;
        emit EmergencyAuthorityChanged(previousValue, newValue);
    }

    function proposeUpgrade(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec) external onlyUpgradeAuthority {
        require(root != bytes32(0), "InstanceController: root=0");
        require(ttlSec != 0, "InstanceController: ttl=0");

        pendingUpgrade = UpgradeProposal({
            root: root,
            uriHash: uriHash,
            policyHash: policyHash,
            createdAt: uint64(block.timestamp),
            ttlSec: ttlSec
        });

        emit UpgradeProposed(root, uriHash, policyHash, ttlSec);
    }

    function activateUpgrade() external onlyUpgradeAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(block.timestamp <= uint256(upgrade.createdAt) + uint256(upgrade.ttlSec), "InstanceController: upgrade expired");

        activeRoot = upgrade.root;
        activeUriHash = upgrade.uriHash;
        activePolicyHash = upgrade.policyHash;

        delete pendingUpgrade;

        emit UpgradeActivated(activeRoot, activeUriHash, activePolicyHash);
    }
}
