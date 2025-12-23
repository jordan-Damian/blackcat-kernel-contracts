pragma solidity ^0.8.24;

interface IReleaseRegistry {
    function isTrustedRoot(bytes32 root) external view returns (bool);
}

/// @notice Per-install trust authority for a single BlackCat deployment.
/// @dev Skeleton contract (not audited, not production-ready).
contract InstanceController {
    uint8 public constant VERSION = 1;
    uint64 public constant MAX_UPGRADE_DELAY_SEC = 30 days;

    struct UpgradeProposal {
        bytes32 root;
        bytes32 uriHash;
        bytes32 policyHash;
        uint64 createdAt;
        uint64 ttlSec;
    }

    /// @notice Factory or caller that initialized this instance (provenance hint).
    address public factory;

    address public rootAuthority;
    address public upgradeAuthority;
    address public emergencyAuthority;
    address public releaseRegistry;
    address public reporterAuthority;

    bool public paused;

    bytes32 public activeRoot;
    bytes32 public activeUriHash;
    bytes32 public activePolicyHash;

    UpgradeProposal public pendingUpgrade;

    uint64 public genesisAt;
    uint64 public lastUpgradeAt;
    uint64 public minUpgradeDelaySec;
    uint64 public lastCheckInAt;
    bool public lastCheckInOk;

    event Initialized(
        address indexed factory,
        address indexed rootAuthority,
        address indexed upgradeAuthority,
        address emergencyAuthority
    );
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event UpgradeProposed(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec);
    event UpgradeCanceled(address indexed by);
    event UpgradeActivated(bytes32 previousRoot, bytes32 root, bytes32 uriHash, bytes32 policyHash);
    event RootAuthorityChanged(address indexed previousValue, address indexed newValue);
    event UpgradeAuthorityChanged(address indexed previousValue, address indexed newValue);
    event EmergencyAuthorityChanged(address indexed previousValue, address indexed newValue);
    event ReleaseRegistryChanged(address indexed previousValue, address indexed newValue);
    event ReporterAuthorityChanged(address indexed previousValue, address indexed newValue);
    event MinUpgradeDelayChanged(uint64 previousValue, uint64 newValue);
    event CheckIn(address indexed by, bool ok, bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash);

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

    modifier onlyReporterAuthority() {
        require(msg.sender == reporterAuthority, "InstanceController: not reporter authority");
        _;
    }

    modifier onlyRootOrUpgradeAuthority() {
        require(
            msg.sender == rootAuthority || msg.sender == upgradeAuthority,
            "InstanceController: not root/upgrade authority"
        );
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
        address releaseRegistry_,
        bytes32 genesisRoot,
        bytes32 genesisUriHash,
        bytes32 genesisPolicyHash
    ) external {
        require(rootAuthority == address(0), "InstanceController: already initialized");
        require(rootAuthority_ != address(0), "InstanceController: root=0");
        require(upgradeAuthority_ != address(0), "InstanceController: upgrade=0");
        require(emergencyAuthority_ != address(0), "InstanceController: emergency=0");
        require(genesisRoot != bytes32(0), "InstanceController: genesisRoot=0");

        factory = msg.sender;
        rootAuthority = rootAuthority_;
        upgradeAuthority = upgradeAuthority_;
        emergencyAuthority = emergencyAuthority_;

        if (releaseRegistry_ != address(0)) {
            require(releaseRegistry_.code.length != 0, "InstanceController: registry not contract");
            require(
                IReleaseRegistry(releaseRegistry_).isTrustedRoot(genesisRoot),
                "InstanceController: genesis root not trusted"
            );
            releaseRegistry = releaseRegistry_;
        }

        genesisAt = uint64(block.timestamp);
        lastUpgradeAt = genesisAt;

        activeRoot = genesisRoot;
        activeUriHash = genesisUriHash;
        activePolicyHash = genesisPolicyHash;

        emit Initialized(factory, rootAuthority_, upgradeAuthority_, emergencyAuthority_);
        emit UpgradeActivated(bytes32(0), genesisRoot, genesisUriHash, genesisPolicyHash);
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

    function setReleaseRegistry(address newValue) external onlyRootAuthority {
        if (newValue != address(0)) {
            require(newValue.code.length != 0, "InstanceController: registry not contract");
        }
        address previousValue = releaseRegistry;
        releaseRegistry = newValue;
        emit ReleaseRegistryChanged(previousValue, newValue);
    }

    function setReporterAuthority(address newValue) external onlyRootAuthority {
        address previousValue = reporterAuthority;
        reporterAuthority = newValue;
        emit ReporterAuthorityChanged(previousValue, newValue);
    }

    function setMinUpgradeDelaySec(uint64 newValue) external onlyRootAuthority {
        require(newValue <= MAX_UPGRADE_DELAY_SEC, "InstanceController: delay too large");
        uint64 previousValue = minUpgradeDelaySec;
        minUpgradeDelaySec = newValue;
        emit MinUpgradeDelayChanged(previousValue, newValue);
    }

    function checkIn(bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash)
        external
        onlyReporterAuthority
    {
        bool ok = (!paused)
            && (observedRoot == activeRoot)
            && (observedUriHash == activeUriHash)
            && (observedPolicyHash == activePolicyHash);

        lastCheckInAt = uint64(block.timestamp);
        lastCheckInOk = ok;

        emit CheckIn(msg.sender, ok, observedRoot, observedUriHash, observedPolicyHash);
    }

    function proposeUpgrade(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec)
        external
        onlyUpgradeAuthority
    {
        require(root != bytes32(0), "InstanceController: root=0");
        require(ttlSec != 0, "InstanceController: ttl=0");

        address registry = releaseRegistry;
        if (registry != address(0)) {
            require(IReleaseRegistry(registry).isTrustedRoot(root), "InstanceController: root not trusted");
        }

        pendingUpgrade = UpgradeProposal({
            root: root, uriHash: uriHash, policyHash: policyHash, createdAt: uint64(block.timestamp), ttlSec: ttlSec
        });

        emit UpgradeProposed(root, uriHash, policyHash, ttlSec);
    }

    function cancelUpgrade() external onlyRootOrUpgradeAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function activateUpgrade() external onlyRootAuthority {
        require(!paused, "InstanceController: paused");
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            block.timestamp >= uint256(upgrade.createdAt) + uint256(minUpgradeDelaySec),
            "InstanceController: upgrade timelocked"
        );
        require(
            block.timestamp <= uint256(upgrade.createdAt) + uint256(upgrade.ttlSec),
            "InstanceController: upgrade expired"
        );

        address registry = releaseRegistry;
        if (registry != address(0)) {
            require(
                IReleaseRegistry(registry).isTrustedRoot(upgrade.root),
                "InstanceController: root not trusted"
            );
        }

        bytes32 previousRoot = activeRoot;
        activeRoot = upgrade.root;
        activeUriHash = upgrade.uriHash;
        activePolicyHash = upgrade.policyHash;

        delete pendingUpgrade;

        lastUpgradeAt = uint64(block.timestamp);

        emit UpgradeActivated(previousRoot, activeRoot, activeUriHash, activePolicyHash);
    }

    function snapshot()
        external
        view
        returns (
            uint8 version,
            bool paused_,
            bytes32 activeRoot_,
            bytes32 activeUriHash_,
            bytes32 activePolicyHash_,
            bytes32 pendingRoot_,
            bytes32 pendingUriHash_,
            bytes32 pendingPolicyHash_,
            uint64 pendingCreatedAt_,
            uint64 pendingTtlSec_,
            uint64 genesisAt_,
            uint64 lastUpgradeAt_
        )
    {
        UpgradeProposal memory p = pendingUpgrade;
        return (
            VERSION,
            paused,
            activeRoot,
            activeUriHash,
            activePolicyHash,
            p.root,
            p.uriHash,
            p.policyHash,
            p.createdAt,
            p.ttlSec,
            genesisAt,
            lastUpgradeAt
        );
    }
}
