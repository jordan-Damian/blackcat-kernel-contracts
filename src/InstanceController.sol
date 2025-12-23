pragma solidity ^0.8.24;

interface IReleaseRegistry {
    function isTrustedRoot(bytes32 root) external view returns (bool);
}

interface IReleaseRegistryGet {
    struct Release {
        bytes32 root;
        bytes32 uriHash;
        bytes32 metaHash;
    }

    function get(bytes32 componentId, uint64 version) external view returns (Release memory);
}

interface IReleaseRegistryByRoot {
    function getByRoot(bytes32 root)
        external
        view
        returns (bytes32 componentId, uint64 version, bytes32 uriHash, bytes32 metaHash, bool revoked);
}

/// @notice Per-install trust authority for a single BlackCat deployment.
/// @dev Skeleton contract (not audited, not production-ready).
contract InstanceController {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatInstanceController"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant ACTIVATE_UPGRADE_TYPEHASH = keccak256(
        "ActivateUpgrade(bytes32 root,bytes32 uriHash,bytes32 policyHash,uint64 createdAt,uint64 ttlSec,uint256 deadline)"
    );
    bytes32 private constant CANCEL_UPGRADE_TYPEHASH = keccak256(
        "CancelUpgrade(bytes32 root,bytes32 uriHash,bytes32 policyHash,uint64 createdAt,uint64 ttlSec,uint256 deadline)"
    );
    bytes32 private constant CHECKIN_TYPEHASH = keccak256(
        "CheckIn(bytes32 observedRoot,bytes32 observedUriHash,bytes32 observedPolicyHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant REPORT_INCIDENT_TYPEHASH =
        keccak256("ReportIncident(bytes32 incidentHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant SET_PAUSED_TYPEHASH =
        keccak256("SetPaused(bool expectedPaused,bool newPaused,uint256 nonce,uint256 deadline)");
    bytes32 private constant ACCEPT_AUTHORITY_TYPEHASH =
        keccak256("AcceptAuthority(bytes32 role,address newAuthority,uint256 nonce,uint256 deadline)");

    bytes32 private constant ROLE_ROOT_AUTHORITY = keccak256("root_authority");
    bytes32 private constant ROLE_UPGRADE_AUTHORITY = keccak256("upgrade_authority");
    bytes32 private constant ROLE_EMERGENCY_AUTHORITY = keccak256("emergency_authority");
    bytes32 private constant ROLE_REPORTER_AUTHORITY = keccak256("reporter_authority");

    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    uint8 public constant VERSION = 1;
    uint64 public constant MAX_UPGRADE_DELAY_SEC = 30 days;
    uint64 public constant MAX_COMPATIBILITY_WINDOW_SEC = 30 days;

    struct UpgradeProposal {
        bytes32 root;
        bytes32 uriHash;
        bytes32 policyHash;
        uint64 createdAt;
        uint64 ttlSec;
    }

    struct CompatibilityState {
        bytes32 root;
        bytes32 uriHash;
        bytes32 policyHash;
        uint64 until;
    }

    /// @notice Factory or caller that initialized this instance (provenance hint).
    address public factory;

    address public rootAuthority;
    address public upgradeAuthority;
    address public emergencyAuthority;
    address public pendingRootAuthority;
    address public pendingUpgradeAuthority;
    address public pendingEmergencyAuthority;

    address public releaseRegistry;
    bool public releaseRegistryLocked;
    bytes32 public expectedComponentId;
    bool public expectedComponentIdLocked;
    address public reporterAuthority;
    address public pendingReporterAuthority;

    bool public paused;
    bool public emergencyCanUnpause;
    bool public emergencyCanUnpauseLocked;
    bool public autoPauseOnBadCheckIn;
    bool public autoPauseOnBadCheckInLocked;

    bytes32 public activeRoot;
    bytes32 public activeUriHash;
    bytes32 public activePolicyHash;

    UpgradeProposal public pendingUpgrade;
    CompatibilityState public compatibilityState;
    uint64 public compatibilityWindowSec;
    bool public compatibilityWindowLocked;

    /// @notice Root-controlled attestation slots (extensibility without contract changes).
    mapping(bytes32 => bytes32) public attestations;
    mapping(bytes32 => uint64) public attestationUpdatedAt;
    mapping(bytes32 => bool) public attestationLocked;

    uint64 public genesisAt;
    uint64 public lastUpgradeAt;
    uint64 public minUpgradeDelaySec;
    bool public minUpgradeDelayLocked;
    uint64 public lastCheckInAt;
    bool public lastCheckInOk;

    uint64 public incidentCount;
    uint64 public lastIncidentAt;
    bytes32 public lastIncidentHash;
    address public lastIncidentBy;

    uint256 public reporterNonce;
    uint256 public incidentNonce;
    uint256 public pauseNonce;

    uint256 public rootAuthorityTransferNonce;
    uint256 public upgradeAuthorityTransferNonce;
    uint256 public emergencyAuthorityTransferNonce;
    uint256 public reporterAuthorityTransferNonce;

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
    event RootAuthorityTransferStarted(address indexed previousValue, address indexed pendingValue);
    event UpgradeAuthorityTransferStarted(address indexed previousValue, address indexed pendingValue);
    event EmergencyAuthorityTransferStarted(address indexed previousValue, address indexed pendingValue);
    event ReporterAuthorityTransferStarted(address indexed previousValue, address indexed pendingValue);
    event RootAuthorityTransferCanceled(address indexed previousValue, address indexed pendingValue);
    event UpgradeAuthorityTransferCanceled(address indexed previousValue, address indexed pendingValue);
    event EmergencyAuthorityTransferCanceled(address indexed previousValue, address indexed pendingValue);
    event ReporterAuthorityTransferCanceled(address indexed previousValue, address indexed pendingValue);
    event ReleaseRegistryChanged(address indexed previousValue, address indexed newValue);
    event ReleaseRegistryLocked(address indexed registry);
    event ExpectedComponentIdChanged(bytes32 indexed previousValue, bytes32 indexed newValue);
    event ExpectedComponentIdLocked(bytes32 indexed componentId);
    event ReporterAuthorityChanged(address indexed previousValue, address indexed newValue);
    event MinUpgradeDelayChanged(uint64 previousValue, uint64 newValue);
    event MinUpgradeDelayLocked(uint64 value);
    event CompatibilityWindowChanged(uint64 previousValue, uint64 newValue);
    event CompatibilityWindowLocked(uint64 value);
    event CompatibilityStateSet(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 until);
    event CompatibilityStateCleared(bytes32 root, bytes32 uriHash, bytes32 policyHash);
    event AttestationSet(bytes32 indexed key, bytes32 previousValue, bytes32 newValue, uint64 at);
    event AttestationLocked(bytes32 indexed key, bytes32 value, uint64 at);
    event AutoPauseOnBadCheckInChanged(bool previousValue, bool newValue);
    event AutoPauseOnBadCheckInLocked(bool value);
    event EmergencyUnpausePolicyChanged(bool previousValue, bool newValue);
    event EmergencyUnpausePolicyLocked(bool value);
    event CheckIn(
        address indexed by, bool ok, bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash
    );
    event IncidentReported(address indexed by, bytes32 incidentHash, uint64 at);
    event AuthoritySignatureConsumed(address indexed authority, bytes32 indexed digest, address indexed relayer);

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

    modifier onlyEmergencyOrRootAuthority() {
        require(
            msg.sender == emergencyAuthority || msg.sender == rootAuthority,
            "InstanceController: not emergency/root authority"
        );
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

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function pause() external onlyEmergencyOrRootAuthority {
        if (!paused) {
            _setPaused(msg.sender, true);
        }
    }

    function unpause() external {
        if (msg.sender == rootAuthority) {
            if (paused) {
                _setPaused(msg.sender, false);
            }
            return;
        }

        require(msg.sender == emergencyAuthority, "InstanceController: not emergency/root authority");
        require(emergencyCanUnpause, "InstanceController: emergency cannot unpause");
        if (paused) {
            _setPaused(msg.sender, false);
        }
    }

    function hashSetPaused(bool expectedPaused, bool newPaused, uint256 deadline) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(SET_PAUSED_TYPEHASH, expectedPaused, newPaused, pauseNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function setPausedAuthorized(bool expectedPaused, bool newPaused, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "InstanceController: expired");
        require(expectedPaused != newPaused, "InstanceController: no-op");
        require(paused == expectedPaused, "InstanceController: paused mismatch");

        bytes32 structHash = keccak256(abi.encode(SET_PAUSED_TYPEHASH, expectedPaused, newPaused, pauseNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address signer = _resolvePauseSigner(digest, signature);
        require(signer != address(0), "InstanceController: invalid pause signature");
        emit AuthoritySignatureConsumed(signer, digest, msg.sender);

        if (!newPaused && !emergencyCanUnpause) {
            require(signer == rootAuthority, "InstanceController: emergency cannot unpause");
        }

        _setPaused(signer, newPaused);
    }

    function startRootAuthorityTransfer(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: root=0");
        rootAuthorityTransferNonce += 1;
        pendingRootAuthority = newValue;
        emit RootAuthorityTransferStarted(rootAuthority, newValue);
    }

    function cancelRootAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingRootAuthority;
        require(pendingValue != address(0), "InstanceController: no pending root");
        pendingRootAuthority = address(0);
        emit RootAuthorityTransferCanceled(rootAuthority, pendingValue);
    }

    function acceptRootAuthority() external {
        address pendingValue = pendingRootAuthority;
        require(pendingValue != address(0), "InstanceController: no pending root");
        require(msg.sender == pendingValue, "InstanceController: not pending root");
        address previousValue = rootAuthority;
        rootAuthority = pendingValue;
        pendingRootAuthority = address(0);
        emit RootAuthorityChanged(previousValue, pendingValue);
    }

    function hashAcceptRootAuthority(address expectedNewAuthority, uint256 deadline) external view returns (bytes32) {
        address pendingValue = pendingRootAuthority;
        require(pendingValue != address(0), "InstanceController: no pending root");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending root mismatch");
        return _hashAcceptAuthority(ROLE_ROOT_AUTHORITY, expectedNewAuthority, rootAuthorityTransferNonce, deadline);
    }

    function acceptRootAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "InstanceController: expired");

        address pendingValue = pendingRootAuthority;
        require(pendingValue != address(0), "InstanceController: no pending root");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending root mismatch");

        bytes32 digest =
            _hashAcceptAuthority(ROLE_ROOT_AUTHORITY, expectedNewAuthority, rootAuthorityTransferNonce, deadline);
        require(
            _isValidSignatureNow(pendingValue, digest, signature), "InstanceController: invalid pending root signature"
        );
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = rootAuthority;
        rootAuthority = pendingValue;
        pendingRootAuthority = address(0);
        emit RootAuthorityChanged(previousValue, pendingValue);
    }

    function startUpgradeAuthorityTransfer(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: upgrade=0");
        upgradeAuthorityTransferNonce += 1;
        pendingUpgradeAuthority = newValue;
        emit UpgradeAuthorityTransferStarted(upgradeAuthority, newValue);
    }

    function cancelUpgradeAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingUpgradeAuthority;
        require(pendingValue != address(0), "InstanceController: no pending upgrade");
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityTransferCanceled(upgradeAuthority, pendingValue);
    }

    function acceptUpgradeAuthority() external {
        address pendingValue = pendingUpgradeAuthority;
        require(pendingValue != address(0), "InstanceController: no pending upgrade");
        require(msg.sender == pendingValue, "InstanceController: not pending upgrade");
        address previousValue = upgradeAuthority;
        upgradeAuthority = pendingValue;
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityChanged(previousValue, pendingValue);
    }

    function hashAcceptUpgradeAuthority(address expectedNewAuthority, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        address pendingValue = pendingUpgradeAuthority;
        require(pendingValue != address(0), "InstanceController: no pending upgrade");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending upgrade mismatch");
        return
            _hashAcceptAuthority(ROLE_UPGRADE_AUTHORITY, expectedNewAuthority, upgradeAuthorityTransferNonce, deadline);
    }

    function acceptUpgradeAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "InstanceController: expired");

        address pendingValue = pendingUpgradeAuthority;
        require(pendingValue != address(0), "InstanceController: no pending upgrade");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending upgrade mismatch");

        bytes32 digest =
            _hashAcceptAuthority(ROLE_UPGRADE_AUTHORITY, expectedNewAuthority, upgradeAuthorityTransferNonce, deadline);
        require(
            _isValidSignatureNow(pendingValue, digest, signature),
            "InstanceController: invalid pending upgrade signature"
        );
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = upgradeAuthority;
        upgradeAuthority = pendingValue;
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityChanged(previousValue, pendingValue);
    }

    function startEmergencyAuthorityTransfer(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: emergency=0");
        emergencyAuthorityTransferNonce += 1;
        pendingEmergencyAuthority = newValue;
        emit EmergencyAuthorityTransferStarted(emergencyAuthority, newValue);
    }

    function cancelEmergencyAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingEmergencyAuthority;
        require(pendingValue != address(0), "InstanceController: no pending emergency");
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityTransferCanceled(emergencyAuthority, pendingValue);
    }

    function acceptEmergencyAuthority() external {
        address pendingValue = pendingEmergencyAuthority;
        require(pendingValue != address(0), "InstanceController: no pending emergency");
        require(msg.sender == pendingValue, "InstanceController: not pending emergency");
        address previousValue = emergencyAuthority;
        emergencyAuthority = pendingValue;
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityChanged(previousValue, pendingValue);
    }

    function hashAcceptEmergencyAuthority(address expectedNewAuthority, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        address pendingValue = pendingEmergencyAuthority;
        require(pendingValue != address(0), "InstanceController: no pending emergency");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending emergency mismatch");
        return
            _hashAcceptAuthority(
                ROLE_EMERGENCY_AUTHORITY, expectedNewAuthority, emergencyAuthorityTransferNonce, deadline
            );
    }

    function acceptEmergencyAuthorityAuthorized(
        address expectedNewAuthority,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "InstanceController: expired");

        address pendingValue = pendingEmergencyAuthority;
        require(pendingValue != address(0), "InstanceController: no pending emergency");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending emergency mismatch");

        bytes32 digest = _hashAcceptAuthority(
            ROLE_EMERGENCY_AUTHORITY, expectedNewAuthority, emergencyAuthorityTransferNonce, deadline
        );
        require(
            _isValidSignatureNow(pendingValue, digest, signature),
            "InstanceController: invalid pending emergency signature"
        );
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = emergencyAuthority;
        emergencyAuthority = pendingValue;
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityChanged(previousValue, pendingValue);
    }

    function setReleaseRegistry(address newValue) external onlyRootAuthority {
        require(!releaseRegistryLocked, "InstanceController: registry locked");

        if (newValue == address(0)) {
            require(expectedComponentId == bytes32(0), "InstanceController: expected component set");
        }

        if (newValue != address(0)) {
            require(newValue.code.length != 0, "InstanceController: registry not contract");
            require(IReleaseRegistry(newValue).isTrustedRoot(activeRoot), "InstanceController: active root not trusted");

            UpgradeProposal memory p = pendingUpgrade;
            if (p.root != bytes32(0)) {
                require(
                    IReleaseRegistry(newValue).isTrustedRoot(p.root), "InstanceController: pending root not trusted"
                );
            }

            CompatibilityState memory compat = compatibilityState;
            if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                require(
                    IReleaseRegistry(newValue).isTrustedRoot(compat.root), "InstanceController: compat root not trusted"
                );
            }

            bytes32 expected = expectedComponentId;
            if (expected != bytes32(0)) {
                _requireRootComponent(newValue, activeRoot, expected);
                if (p.root != bytes32(0)) {
                    _requireRootComponent(newValue, p.root, expected);
                }
                if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                    _requireRootComponent(newValue, compat.root, expected);
                }
            }
        }
        address previousValue = releaseRegistry;
        releaseRegistry = newValue;
        emit ReleaseRegistryChanged(previousValue, newValue);
    }

    function lockReleaseRegistry() external onlyRootAuthority {
        require(!releaseRegistryLocked, "InstanceController: registry locked");
        address registry = releaseRegistry;
        require(registry != address(0), "InstanceController: no registry");
        releaseRegistryLocked = true;
        emit ReleaseRegistryLocked(registry);
    }

    function setExpectedComponentId(bytes32 newValue) external onlyRootAuthority {
        require(!expectedComponentIdLocked, "InstanceController: expected component locked");

        if (newValue != bytes32(0)) {
            address registry = releaseRegistry;
            require(registry != address(0), "InstanceController: no registry");

            _requireRootComponent(registry, activeRoot, newValue);

            UpgradeProposal memory p = pendingUpgrade;
            if (p.root != bytes32(0)) {
                _requireRootComponent(registry, p.root, newValue);
            }

            CompatibilityState memory compat = compatibilityState;
            if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                _requireRootComponent(registry, compat.root, newValue);
            }
        }

        bytes32 previousValue = expectedComponentId;
        expectedComponentId = newValue;
        emit ExpectedComponentIdChanged(previousValue, newValue);
    }

    function lockExpectedComponentId() external onlyRootAuthority {
        require(!expectedComponentIdLocked, "InstanceController: expected component locked");
        bytes32 componentId = expectedComponentId;
        require(componentId != bytes32(0), "InstanceController: componentId=0");
        expectedComponentIdLocked = true;
        emit ExpectedComponentIdLocked(componentId);
    }

    function startReporterAuthorityTransfer(address newValue) external onlyRootAuthority {
        require(newValue != address(0), "InstanceController: reporter=0");
        reporterAuthorityTransferNonce += 1;
        pendingReporterAuthority = newValue;
        emit ReporterAuthorityTransferStarted(reporterAuthority, newValue);
    }

    function cancelReporterAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingReporterAuthority;
        require(pendingValue != address(0), "InstanceController: no pending reporter");
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityTransferCanceled(reporterAuthority, pendingValue);
    }

    function acceptReporterAuthority() external {
        address pendingValue = pendingReporterAuthority;
        require(pendingValue != address(0), "InstanceController: no pending reporter");
        require(msg.sender == pendingValue, "InstanceController: not pending reporter");
        address previousValue = reporterAuthority;
        reporterAuthority = pendingValue;
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityChanged(previousValue, pendingValue);
    }

    function hashAcceptReporterAuthority(address expectedNewAuthority, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        address pendingValue = pendingReporterAuthority;
        require(pendingValue != address(0), "InstanceController: no pending reporter");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending reporter mismatch");
        return
            _hashAcceptAuthority(
                ROLE_REPORTER_AUTHORITY, expectedNewAuthority, reporterAuthorityTransferNonce, deadline
            );
    }

    function acceptReporterAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        require(block.timestamp <= deadline, "InstanceController: expired");

        address pendingValue = pendingReporterAuthority;
        require(pendingValue != address(0), "InstanceController: no pending reporter");
        require(pendingValue == expectedNewAuthority, "InstanceController: pending reporter mismatch");

        bytes32 digest = _hashAcceptAuthority(
            ROLE_REPORTER_AUTHORITY, expectedNewAuthority, reporterAuthorityTransferNonce, deadline
        );
        require(
            _isValidSignatureNow(pendingValue, digest, signature),
            "InstanceController: invalid pending reporter signature"
        );
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = reporterAuthority;
        reporterAuthority = pendingValue;
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityChanged(previousValue, pendingValue);
    }

    function clearReporterAuthority() external onlyRootAuthority {
        address previousValue = reporterAuthority;
        reporterAuthority = address(0);
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityChanged(previousValue, address(0));
    }

    function setMinUpgradeDelaySec(uint64 newValue) external onlyRootAuthority {
        require(!minUpgradeDelayLocked, "InstanceController: delay locked");
        require(newValue <= MAX_UPGRADE_DELAY_SEC, "InstanceController: delay too large");
        uint64 previousValue = minUpgradeDelaySec;
        minUpgradeDelaySec = newValue;
        emit MinUpgradeDelayChanged(previousValue, newValue);
    }

    function lockMinUpgradeDelay() external onlyRootAuthority {
        require(!minUpgradeDelayLocked, "InstanceController: delay locked");
        require(minUpgradeDelaySec != 0, "InstanceController: delay=0");
        minUpgradeDelayLocked = true;
        emit MinUpgradeDelayLocked(minUpgradeDelaySec);
    }

    function lockEmergencyCanUnpause() external onlyRootAuthority {
        require(!emergencyCanUnpauseLocked, "InstanceController: unpause policy locked");
        emergencyCanUnpauseLocked = true;
        emit EmergencyUnpausePolicyLocked(emergencyCanUnpause);
    }

    function setEmergencyCanUnpause(bool newValue) external onlyRootAuthority {
        require(!emergencyCanUnpauseLocked, "InstanceController: unpause policy locked");
        bool previousValue = emergencyCanUnpause;
        emergencyCanUnpause = newValue;
        emit EmergencyUnpausePolicyChanged(previousValue, newValue);
    }

    function setCompatibilityWindowSec(uint64 newValue) external onlyRootAuthority {
        require(!compatibilityWindowLocked, "InstanceController: window locked");
        require(newValue <= MAX_COMPATIBILITY_WINDOW_SEC, "InstanceController: window too large");
        uint64 previousValue = compatibilityWindowSec;
        compatibilityWindowSec = newValue;
        emit CompatibilityWindowChanged(previousValue, newValue);
    }

    function lockCompatibilityWindow() external onlyRootAuthority {
        require(!compatibilityWindowLocked, "InstanceController: window locked");
        compatibilityWindowLocked = true;
        emit CompatibilityWindowLocked(compatibilityWindowSec);
    }

    function clearCompatibilityState() external onlyRootAuthority {
        CompatibilityState memory compat = compatibilityState;
        require(compat.root != bytes32(0), "InstanceController: no compat state");
        delete compatibilityState;
        emit CompatibilityStateCleared(compat.root, compat.uriHash, compat.policyHash);
    }

    function setAttestation(bytes32 key, bytes32 value) external onlyRootAuthority {
        require(key != bytes32(0), "InstanceController: key=0");
        require(!attestationLocked[key], "InstanceController: attestation locked");

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);
    }

    function setAttestationExpected(bytes32 key, bytes32 expectedPrevious, bytes32 value) external onlyRootAuthority {
        require(key != bytes32(0), "InstanceController: key=0");
        require(!attestationLocked[key], "InstanceController: attestation locked");
        require(attestations[key] == expectedPrevious, "InstanceController: attestation mismatch");

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);
    }

    function clearAttestation(bytes32 key) external onlyRootAuthority {
        require(key != bytes32(0), "InstanceController: key=0");
        require(!attestationLocked[key], "InstanceController: attestation locked");
        bytes32 previousValue = attestations[key];
        require(previousValue != bytes32(0), "InstanceController: attestation already cleared");

        attestations[key] = bytes32(0);
        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, bytes32(0), at);
    }

    function setAttestationAndLock(bytes32 key, bytes32 value) external onlyRootAuthority {
        require(key != bytes32(0), "InstanceController: key=0");
        require(value != bytes32(0), "InstanceController: value=0");
        require(!attestationLocked[key], "InstanceController: attestation locked");

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);

        attestationLocked[key] = true;
        emit AttestationLocked(key, value, at);
    }

    function lockAttestationKey(bytes32 key) external onlyRootAuthority {
        require(key != bytes32(0), "InstanceController: key=0");
        require(!attestationLocked[key], "InstanceController: attestation locked");

        bytes32 value = attestations[key];
        require(value != bytes32(0), "InstanceController: no attestation");

        uint64 at = uint64(block.timestamp);
        attestationLocked[key] = true;
        emit AttestationLocked(key, value, at);
    }

    function setAutoPauseOnBadCheckIn(bool newValue) external onlyRootAuthority {
        require(!autoPauseOnBadCheckInLocked, "InstanceController: auto-pause locked");
        bool previousValue = autoPauseOnBadCheckIn;
        autoPauseOnBadCheckIn = newValue;
        emit AutoPauseOnBadCheckInChanged(previousValue, newValue);
    }

    function lockAutoPauseOnBadCheckIn() external onlyRootAuthority {
        require(!autoPauseOnBadCheckInLocked, "InstanceController: auto-pause locked");
        autoPauseOnBadCheckInLocked = true;
        emit AutoPauseOnBadCheckInLocked(autoPauseOnBadCheckIn);
    }

    function isAcceptedState(bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash)
        public
        view
        returns (bool)
    {
        if (observedRoot == activeRoot && observedUriHash == activeUriHash && observedPolicyHash == activePolicyHash) {
            return _isRootTrusted(observedRoot);
        }

        CompatibilityState memory compat = compatibilityState;
        if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
            if (
                observedRoot == compat.root && observedUriHash == compat.uriHash
                    && observedPolicyHash == compat.policyHash
            ) {
                return _isRootTrusted(observedRoot);
            }
        }

        return false;
    }

    function checkIn(bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash)
        external
        onlyReporterAuthority
    {
        reporterNonce += 1;
        _checkIn(msg.sender, observedRoot, observedUriHash, observedPolicyHash);
    }

    function hashCheckIn(bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(CHECKIN_TYPEHASH, observedRoot, observedUriHash, observedPolicyHash, reporterNonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function checkInAuthorized(
        bytes32 observedRoot,
        bytes32 observedUriHash,
        bytes32 observedPolicyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "InstanceController: expired");
        address reporter = reporterAuthority;
        require(reporter != address(0), "InstanceController: reporter not set");

        bytes32 structHash = keccak256(
            abi.encode(CHECKIN_TYPEHASH, observedRoot, observedUriHash, observedPolicyHash, reporterNonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        require(_isValidSignatureNow(reporter, digest, signature), "InstanceController: invalid reporter signature");
        emit AuthoritySignatureConsumed(reporter, digest, msg.sender);

        reporterNonce += 1;
        _checkIn(reporter, observedRoot, observedUriHash, observedPolicyHash);
    }

    function reportIncident(bytes32 incidentHash) external {
        require(incidentHash != bytes32(0), "InstanceController: incidentHash=0");
        require(
            msg.sender == rootAuthority || msg.sender == emergencyAuthority || msg.sender == reporterAuthority,
            "InstanceController: not incident reporter"
        );

        incidentNonce += 1;
        _reportIncident(msg.sender, incidentHash);
    }

    function hashReportIncident(bytes32 incidentHash, uint256 deadline) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(REPORT_INCIDENT_TYPEHASH, incidentHash, incidentNonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function reportIncidentAuthorized(bytes32 incidentHash, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "InstanceController: expired");
        require(incidentHash != bytes32(0), "InstanceController: incidentHash=0");

        bytes32 structHash = keccak256(abi.encode(REPORT_INCIDENT_TYPEHASH, incidentHash, incidentNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address authority = _resolveIncidentSigner(digest, signature);
        require(authority != address(0), "InstanceController: invalid incident signature");
        emit AuthoritySignatureConsumed(authority, digest, msg.sender);

        incidentNonce += 1;
        _reportIncident(authority, incidentHash);
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

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            require(registry != address(0), "InstanceController: no registry");
            _requireRootComponent(registry, root, expected);
        }

        pendingUpgrade = UpgradeProposal({
            root: root, uriHash: uriHash, policyHash: policyHash, createdAt: uint64(block.timestamp), ttlSec: ttlSec
        });

        emit UpgradeProposed(root, uriHash, policyHash, ttlSec);
    }

    function proposeUpgradeByRelease(bytes32 componentId, uint64 version, bytes32 policyHash, uint64 ttlSec)
        external
        onlyUpgradeAuthority
    {
        require(componentId != bytes32(0), "InstanceController: componentId=0");
        require(version != 0, "InstanceController: version=0");
        require(ttlSec != 0, "InstanceController: ttl=0");

        address registry = releaseRegistry;
        require(registry != address(0), "InstanceController: no registry");

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            require(componentId == expected, "InstanceController: component mismatch");
        }

        try IReleaseRegistryGet(registry).get(componentId, version) returns (IReleaseRegistryGet.Release memory rel) {
            require(rel.root != bytes32(0), "InstanceController: release not found");
            require(IReleaseRegistry(registry).isTrustedRoot(rel.root), "InstanceController: root not trusted");

            pendingUpgrade = UpgradeProposal({
                root: rel.root,
                uriHash: rel.uriHash,
                policyHash: policyHash,
                createdAt: uint64(block.timestamp),
                ttlSec: ttlSec
            });

            emit UpgradeProposed(rel.root, rel.uriHash, policyHash, ttlSec);
        } catch {
            revert("InstanceController: registry missing get");
        }
    }

    function cancelUpgrade() external onlyRootOrUpgradeAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function cancelUpgradeExpected(bytes32 root, bytes32 uriHash, bytes32 policyHash)
        external
        onlyRootOrUpgradeAuthority
    {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );
        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function hashCancelUpgrade(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );

        bytes32 structHash = keccak256(
            abi.encode(CANCEL_UPGRADE_TYPEHASH, root, uriHash, policyHash, upgrade.createdAt, upgrade.ttlSec, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function cancelUpgradeAuthorized(
        bytes32 root,
        bytes32 uriHash,
        bytes32 policyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "InstanceController: expired");

        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );

        bytes32 structHash = keccak256(
            abi.encode(CANCEL_UPGRADE_TYPEHASH, root, uriHash, policyHash, upgrade.createdAt, upgrade.ttlSec, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        require(_isValidSignatureNow(rootAuthority, digest, signature), "InstanceController: invalid root signature");
        emit AuthoritySignatureConsumed(rootAuthority, digest, msg.sender);

        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function activateUpgrade() external onlyRootAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        _activateUpgrade(upgrade);
    }

    function activateUpgradeExpected(bytes32 root, bytes32 uriHash, bytes32 policyHash) external onlyRootAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );
        _activateUpgrade(upgrade);
    }

    function hashActivateUpgrade(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                ACTIVATE_UPGRADE_TYPEHASH, root, uriHash, policyHash, upgrade.createdAt, upgrade.ttlSec, deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function activateUpgradeAuthorized(
        bytes32 root,
        bytes32 uriHash,
        bytes32 policyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "InstanceController: expired");

        UpgradeProposal memory upgrade = pendingUpgrade;
        require(upgrade.root != bytes32(0), "InstanceController: no pending upgrade");
        require(
            upgrade.root == root && upgrade.uriHash == uriHash && upgrade.policyHash == policyHash,
            "InstanceController: pending mismatch"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                ACTIVATE_UPGRADE_TYPEHASH, root, uriHash, policyHash, upgrade.createdAt, upgrade.ttlSec, deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        require(_isValidSignatureNow(rootAuthority, digest, signature), "InstanceController: invalid root signature");
        emit AuthoritySignatureConsumed(rootAuthority, digest, msg.sender);

        _activateUpgrade(upgrade);
    }

    function _activateUpgrade(UpgradeProposal memory upgrade) private {
        require(!paused, "InstanceController: paused");
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
            require(IReleaseRegistry(registry).isTrustedRoot(upgrade.root), "InstanceController: root not trusted");
        }

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            require(registry != address(0), "InstanceController: no registry");
            _requireRootComponent(registry, upgrade.root, expected);
        }

        bytes32 previousRoot = activeRoot;
        bytes32 previousUriHash = activeUriHash;
        bytes32 previousPolicyHash = activePolicyHash;
        activeRoot = upgrade.root;
        activeUriHash = upgrade.uriHash;
        activePolicyHash = upgrade.policyHash;

        delete pendingUpgrade;

        lastUpgradeAt = uint64(block.timestamp);

        uint64 windowSec = compatibilityWindowSec;
        if (windowSec != 0) {
            uint64 until = uint64(block.timestamp + windowSec);
            compatibilityState = CompatibilityState({
                root: previousRoot, uriHash: previousUriHash, policyHash: previousPolicyHash, until: until
            });
            emit CompatibilityStateSet(previousRoot, previousUriHash, previousPolicyHash, until);
        } else {
            CompatibilityState memory compat = compatibilityState;
            if (compat.root != bytes32(0)) {
                delete compatibilityState;
                emit CompatibilityStateCleared(compat.root, compat.uriHash, compat.policyHash);
            }
        }

        emit UpgradeActivated(previousRoot, activeRoot, activeUriHash, activePolicyHash);
    }

    function _isRootTrusted(bytes32 root) private view returns (bool) {
        address registry = releaseRegistry;
        if (registry == address(0)) {
            return true;
        }

        try IReleaseRegistry(registry).isTrustedRoot(root) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
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
        require(signature.length == 65, "InstanceController: bad signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "InstanceController: bad v");
        require(uint256(s) <= SECP256K1N_HALF, "InstanceController: bad s");

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "InstanceController: bad signature");
        return recovered;
    }

    function _recordIncident(address by, bytes32 incidentHash) private {
        incidentCount += 1;
        lastIncidentAt = uint64(block.timestamp);
        lastIncidentHash = incidentHash;
        lastIncidentBy = by;
        emit IncidentReported(by, incidentHash, uint64(block.timestamp));
    }

    function _checkIn(address by, bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash) private {
        bool ok = (!paused) && isAcceptedState(observedRoot, observedUriHash, observedPolicyHash);

        lastCheckInAt = uint64(block.timestamp);
        lastCheckInOk = ok;

        emit CheckIn(by, ok, observedRoot, observedUriHash, observedPolicyHash);

        if (autoPauseOnBadCheckIn && !paused && !ok) {
            _recordIncident(
                by,
                keccak256(
                    abi.encodePacked(
                        "bad_checkin",
                        observedRoot,
                        observedUriHash,
                        observedPolicyHash,
                        activeRoot,
                        activeUriHash,
                        activePolicyHash
                    )
                )
            );
            _setPaused(by, true);
        }
    }

    function _reportIncident(address by, bytes32 incidentHash) private {
        _recordIncident(by, incidentHash);

        if (!paused) {
            _setPaused(by, true);
        }
    }

    function _resolveIncidentSigner(bytes32 digest, bytes memory signature) private view returns (address) {
        address root = rootAuthority;
        if (_isValidSignatureNow(root, digest, signature)) {
            return root;
        }

        address emergency = emergencyAuthority;
        if (_isValidSignatureNow(emergency, digest, signature)) {
            return emergency;
        }

        address reporter = reporterAuthority;
        if (reporter != address(0) && _isValidSignatureNow(reporter, digest, signature)) {
            return reporter;
        }

        return address(0);
    }

    function _resolvePauseSigner(bytes32 digest, bytes memory signature) private view returns (address) {
        address root = rootAuthority;
        if (_isValidSignatureNow(root, digest, signature)) {
            return root;
        }

        address emergency = emergencyAuthority;
        if (_isValidSignatureNow(emergency, digest, signature)) {
            return emergency;
        }

        return address(0);
    }

    function _setPaused(address by, bool newPaused) private {
        if (paused == newPaused) {
            return;
        }

        pauseNonce += 1;
        paused = newPaused;
        if (newPaused) {
            emit Paused(by);
        } else {
            emit Unpaused(by);
        }
    }

    function _hashAcceptAuthority(bytes32 role, address newAuthority, uint256 nonce, uint256 deadline)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(ACCEPT_AUTHORITY_TYPEHASH, role, newAuthority, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _requireRootComponent(address registry, bytes32 root, bytes32 componentId) private view {
        require(root != bytes32(0), "InstanceController: root=0");
        require(componentId != bytes32(0), "InstanceController: componentId=0");

        try IReleaseRegistryByRoot(registry).getByRoot(root) returns (
            bytes32 foundComponentId, uint64, bytes32, bytes32, bool
        ) {
            require(foundComponentId != bytes32(0), "InstanceController: root unknown");
            require(foundComponentId == componentId, "InstanceController: component mismatch");
        } catch {
            revert("InstanceController: registry missing getByRoot");
        }
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

    /// @notice Operational snapshot to reduce `eth_call` count for monitoring/diagnostics.
    /// @dev `snapshot()` remains stable for runtime enforcement; this function is additive.
    function snapshotV2()
        external
        view
        returns (
            bool autoPauseOnBadCheckIn_,
            address releaseRegistry_,
            address reporterAuthority_,
            uint64 minUpgradeDelaySec_,
            uint64 lastCheckInAt_,
            bool lastCheckInOk_,
            uint64 incidentCount_,
            uint64 lastIncidentAt_,
            bytes32 lastIncidentHash_,
            address lastIncidentBy_,
            uint256 flags_
        )
    {
        uint256 flags = 0;
        if (emergencyCanUnpause) {
            flags |= 1;
        }
        if (releaseRegistryLocked) {
            flags |= 2;
        }
        if (minUpgradeDelayLocked) {
            flags |= 4;
        }
        if (emergencyCanUnpauseLocked) {
            flags |= 8;
        }
        if (autoPauseOnBadCheckInLocked) {
            flags |= 16;
        }
        if (compatibilityWindowLocked) {
            flags |= 32;
        }
        if (expectedComponentIdLocked) {
            flags |= 64;
        }

        return (
            autoPauseOnBadCheckIn,
            releaseRegistry,
            reporterAuthority,
            minUpgradeDelaySec,
            lastCheckInAt,
            lastCheckInOk,
            incidentCount,
            lastIncidentAt,
            lastIncidentHash,
            lastIncidentBy,
            flags
        );
    }
}
