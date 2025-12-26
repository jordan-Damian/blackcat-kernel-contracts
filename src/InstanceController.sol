/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

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
        "ActivateUpgrade(bytes32 root,bytes32 uriHash,bytes32 policyHash,uint256 proposalNonce,uint64 createdAt,uint64 ttlSec,uint256 deadline)"
    );
    bytes32 private constant CANCEL_UPGRADE_TYPEHASH = keccak256(
        "CancelUpgrade(bytes32 root,bytes32 uriHash,bytes32 policyHash,uint256 proposalNonce,uint64 createdAt,uint64 ttlSec,uint256 deadline)"
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
    bytes32 private constant ROLLBACK_COMPATIBILITY_TYPEHASH = keccak256(
        "RollbackCompatibility(bytes32 compatRoot,bytes32 compatUriHash,bytes32 compatPolicyHash,uint64 until,uint256 nonce,uint256 deadline)"
    );

    bytes32 private constant ROLE_ROOT_AUTHORITY = keccak256("root_authority");
    bytes32 private constant ROLE_UPGRADE_AUTHORITY = keccak256("upgrade_authority");
    bytes32 private constant ROLE_EMERGENCY_AUTHORITY = keccak256("emergency_authority");
    bytes32 private constant ROLE_REPORTER_AUTHORITY = keccak256("reporter_authority");

    bytes32 private constant INCIDENT_STALE_CHECKIN = keccak256("stale_checkin");
    bytes32 private constant INCIDENT_ACTIVE_ROOT_UNTRUSTED = keccak256("active_root_untrusted");

    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant EIP2098_S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    uint8 private constant VERSION = 1;
    uint64 private constant MAX_UPGRADE_DELAY_SEC = 30 days;
    uint64 private constant MAX_UPGRADE_TTL_SEC = 30 days;
    uint64 private constant MAX_COMPATIBILITY_WINDOW_SEC = 30 days;
    uint64 private constant MAX_CHECKIN_AGE_SEC = 30 days;

    error NotRootAuthority();
    error NotUpgradeAuthority();
    error NotEmergencyAuthority();
    error NotEmergencyOrRootAuthority();
    error NotReporterAuthority();
    error NotRootOrUpgradeAuthority();

    error AlreadyInitialized();
    error ZeroRootAuthority();
    error ZeroUpgradeAuthority();
    error ZeroEmergencyAuthority();
    error ZeroReporterAuthority();
    error ZeroGenesisRoot();
    error RegistryNotContract();
    error RegistryMissingGet();
    error RegistryMissingGetByRoot();
    error RootNotTrusted();
    error GenesisRootNotTrusted();
    error ActiveRootNotTrusted();
    error PendingRootNotTrusted();
    error CompatRootNotTrusted();

    error Expired();
    error NoOp();
    error PausedMismatch();
    error InvalidPauseSignature();
    error EmergencyCannotUnpause();

    error NoPendingRootAuthority();
    error NoPendingUpgradeAuthority();
    error NoPendingEmergencyAuthority();
    error NoPendingReporterAuthority();
    error NotPendingRootAuthority();
    error NotPendingUpgradeAuthority();
    error NotPendingEmergencyAuthority();
    error NotPendingReporterAuthority();
    error PendingAuthorityMismatch();
    error InvalidPendingAuthoritySignature();

    error ReleaseRegistryPointerLocked();
    error NoReleaseRegistry();
    error ExpectedComponentSet();
    error ExpectedComponentLocked();
    error ZeroComponentId();
    error ComponentMismatch();
    error RootUnknown();

    error DelayLocked();
    error DelayTooLarge();
    error DelayZero();

    error EmergencyUnpausePolicyIsLocked();

    error WindowLocked();
    error WindowTooLarge();
    error NoCompatibilityState();
    error CompatibilityExpired();

    error KeyZero();
    error ValueZero();
    error AttestationKeyIsLocked();
    error AttestationMismatch();
    error AttestationAlreadyCleared();
    error NoAttestation();

    error AutoPauseLocked();
    error CheckInAgeLocked();
    error CheckInAgeTooLarge();
    error CheckInAgeZero();
    error FinalizeMismatch();
    error ReporterNotSet();
    error InvalidReporterSignature();

    error IncidentHashZero();
    error NotIncidentReporter();
    error InvalidIncidentSignature();

    error RootZero();
    error TtlZero();
    error TtlTooLarge();
    error VersionZero();
    error ReleaseNotFound();
    error NoPendingUpgrade();
    error PendingMismatch();
    error InvalidRootSignature();
    error UpgradeTimelocked();
    error UpgradeExpired();

    error BadSignatureLength();
    error BadV();
    error BadS();
    error BadSignature();

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
    uint256 public pendingUpgradeNonce;
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
    uint64 public maxCheckInAgeSec;
    bool public maxCheckInAgeLocked;
    uint64 public lastCheckInAt;
    bool public lastCheckInOk;

    uint64 public incidentCount;
    uint64 public lastIncidentAt;
    bytes32 public lastIncidentHash;
    address public lastIncidentBy;

    uint256 public reporterNonce;
    uint256 public incidentNonce;
    uint256 public pauseNonce;
    uint256 public rollbackNonce;

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
    event UpgradeProposed(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec, uint256 proposalNonce);
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
    event MaxCheckInAgeChanged(uint64 previousValue, uint64 newValue);
    event MaxCheckInAgeLocked(uint64 value);
    event CompatibilityWindowChanged(uint64 previousValue, uint64 newValue);
    event CompatibilityWindowLocked(uint64 value);
    event CompatibilityStateSet(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 until);
    event CompatibilityStateCleared(bytes32 root, bytes32 uriHash, bytes32 policyHash);
    event RolledBackToCompatibility(bytes32 previousRoot, bytes32 newRoot, bytes32 uriHash, bytes32 policyHash);
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
        _requireRootAuthority();
        _;
    }

    modifier onlyUpgradeAuthority() {
        _requireUpgradeAuthority();
        _;
    }

    modifier onlyEmergencyOrRootAuthority() {
        _requireEmergencyOrRootAuthority();
        _;
    }

    modifier onlyReporterAuthority() {
        _requireReporterAuthority();
        _;
    }

    modifier onlyRootOrUpgradeAuthority() {
        _requireRootOrUpgradeAuthority();
        _;
    }

    function _requireRootAuthority() private view {
        if (msg.sender != rootAuthority) revert NotRootAuthority();
    }

    function _requireUpgradeAuthority() private view {
        if (msg.sender != upgradeAuthority) revert NotUpgradeAuthority();
    }

    function _requireEmergencyOrRootAuthority() private view {
        if (msg.sender != emergencyAuthority && msg.sender != rootAuthority) revert NotEmergencyOrRootAuthority();
    }

    function _requireReporterAuthority() private view {
        if (msg.sender != reporterAuthority) revert NotReporterAuthority();
    }

    function _requireRootOrUpgradeAuthority() private view {
        if (msg.sender != rootAuthority && msg.sender != upgradeAuthority) revert NotRootOrUpgradeAuthority();
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
        if (rootAuthority != address(0)) revert AlreadyInitialized();
        if (rootAuthority_ == address(0)) revert ZeroRootAuthority();
        if (upgradeAuthority_ == address(0)) revert ZeroUpgradeAuthority();
        if (emergencyAuthority_ == address(0)) revert ZeroEmergencyAuthority();
        if (genesisRoot == bytes32(0)) revert ZeroGenesisRoot();

        factory = msg.sender;
        rootAuthority = rootAuthority_;
        upgradeAuthority = upgradeAuthority_;
        emergencyAuthority = emergencyAuthority_;

        if (releaseRegistry_ != address(0)) {
            if (releaseRegistry_.code.length == 0) revert RegistryNotContract();
            if (!IReleaseRegistry(releaseRegistry_).isTrustedRoot(genesisRoot)) revert GenesisRootNotTrusted();
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

        if (msg.sender != emergencyAuthority) revert NotEmergencyOrRootAuthority();
        if (!emergencyCanUnpause) revert EmergencyCannotUnpause();
        if (paused) {
            _setPaused(msg.sender, false);
        }
    }

    function setPausedAuthorized(bool expectedPaused, bool newPaused, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert Expired();
        if (expectedPaused == newPaused) revert NoOp();
        if (paused != expectedPaused) revert PausedMismatch();

        bytes32 structHash = keccak256(abi.encode(SET_PAUSED_TYPEHASH, expectedPaused, newPaused, pauseNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address signer = _resolvePauseSigner(digest, signature);
        if (signer == address(0)) revert InvalidPauseSignature();
        emit AuthoritySignatureConsumed(signer, digest, msg.sender);

        if (!newPaused && !emergencyCanUnpause) {
            if (signer != rootAuthority) revert EmergencyCannotUnpause();
        }

        _setPaused(signer, newPaused);
    }

    function startRootAuthorityTransfer(address newValue) external onlyRootAuthority {
        if (newValue == address(0)) revert ZeroRootAuthority();
        unchecked {
            rootAuthorityTransferNonce += 1;
        }
        pendingRootAuthority = newValue;
        emit RootAuthorityTransferStarted(rootAuthority, newValue);
    }

    function cancelRootAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingRootAuthority;
        if (pendingValue == address(0)) revert NoPendingRootAuthority();
        pendingRootAuthority = address(0);
        emit RootAuthorityTransferCanceled(rootAuthority, pendingValue);
    }

    function acceptRootAuthority() external {
        address pendingValue = pendingRootAuthority;
        if (pendingValue == address(0)) revert NoPendingRootAuthority();
        if (msg.sender != pendingValue) revert NotPendingRootAuthority();
        address previousValue = rootAuthority;
        rootAuthority = pendingValue;
        pendingRootAuthority = address(0);
        emit RootAuthorityChanged(previousValue, pendingValue);
    }

    function acceptRootAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert Expired();

        address pendingValue = pendingRootAuthority;
        if (pendingValue == address(0)) revert NoPendingRootAuthority();
        if (pendingValue != expectedNewAuthority) revert PendingAuthorityMismatch();

        bytes32 digest =
            _hashAcceptAuthority(ROLE_ROOT_AUTHORITY, expectedNewAuthority, rootAuthorityTransferNonce, deadline);
        if (!_isValidSignatureNow(pendingValue, digest, signature)) revert InvalidPendingAuthoritySignature();
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = rootAuthority;
        rootAuthority = pendingValue;
        pendingRootAuthority = address(0);
        emit RootAuthorityChanged(previousValue, pendingValue);
    }

    function startUpgradeAuthorityTransfer(address newValue) external onlyRootAuthority {
        if (newValue == address(0)) revert ZeroUpgradeAuthority();
        unchecked {
            upgradeAuthorityTransferNonce += 1;
        }
        pendingUpgradeAuthority = newValue;
        emit UpgradeAuthorityTransferStarted(upgradeAuthority, newValue);
    }

    function cancelUpgradeAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingUpgradeAuthority;
        if (pendingValue == address(0)) revert NoPendingUpgradeAuthority();
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityTransferCanceled(upgradeAuthority, pendingValue);
    }

    function acceptUpgradeAuthority() external {
        address pendingValue = pendingUpgradeAuthority;
        if (pendingValue == address(0)) revert NoPendingUpgradeAuthority();
        if (msg.sender != pendingValue) revert NotPendingUpgradeAuthority();
        address previousValue = upgradeAuthority;
        upgradeAuthority = pendingValue;
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityChanged(previousValue, pendingValue);
    }

    function acceptUpgradeAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert Expired();

        address pendingValue = pendingUpgradeAuthority;
        if (pendingValue == address(0)) revert NoPendingUpgradeAuthority();
        if (pendingValue != expectedNewAuthority) revert PendingAuthorityMismatch();

        bytes32 digest =
            _hashAcceptAuthority(ROLE_UPGRADE_AUTHORITY, expectedNewAuthority, upgradeAuthorityTransferNonce, deadline);
        if (!_isValidSignatureNow(pendingValue, digest, signature)) revert InvalidPendingAuthoritySignature();
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = upgradeAuthority;
        upgradeAuthority = pendingValue;
        pendingUpgradeAuthority = address(0);
        emit UpgradeAuthorityChanged(previousValue, pendingValue);
    }

    function startEmergencyAuthorityTransfer(address newValue) external onlyRootAuthority {
        if (newValue == address(0)) revert ZeroEmergencyAuthority();
        unchecked {
            emergencyAuthorityTransferNonce += 1;
        }
        pendingEmergencyAuthority = newValue;
        emit EmergencyAuthorityTransferStarted(emergencyAuthority, newValue);
    }

    function cancelEmergencyAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingEmergencyAuthority;
        if (pendingValue == address(0)) revert NoPendingEmergencyAuthority();
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityTransferCanceled(emergencyAuthority, pendingValue);
    }

    function acceptEmergencyAuthority() external {
        address pendingValue = pendingEmergencyAuthority;
        if (pendingValue == address(0)) revert NoPendingEmergencyAuthority();
        if (msg.sender != pendingValue) revert NotPendingEmergencyAuthority();
        address previousValue = emergencyAuthority;
        emergencyAuthority = pendingValue;
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityChanged(previousValue, pendingValue);
    }

    function acceptEmergencyAuthorityAuthorized(
        address expectedNewAuthority,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert Expired();

        address pendingValue = pendingEmergencyAuthority;
        if (pendingValue == address(0)) revert NoPendingEmergencyAuthority();
        if (pendingValue != expectedNewAuthority) revert PendingAuthorityMismatch();

        bytes32 digest = _hashAcceptAuthority(
            ROLE_EMERGENCY_AUTHORITY, expectedNewAuthority, emergencyAuthorityTransferNonce, deadline
        );
        if (!_isValidSignatureNow(pendingValue, digest, signature)) revert InvalidPendingAuthoritySignature();
        emit AuthoritySignatureConsumed(pendingValue, digest, msg.sender);

        address previousValue = emergencyAuthority;
        emergencyAuthority = pendingValue;
        pendingEmergencyAuthority = address(0);
        emit EmergencyAuthorityChanged(previousValue, pendingValue);
    }

    function setReleaseRegistry(address newValue) external onlyRootAuthority {
        if (releaseRegistryLocked) revert ReleaseRegistryPointerLocked();

        if (newValue == address(0)) {
            if (expectedComponentId != bytes32(0)) revert ExpectedComponentSet();
        }

        if (newValue != address(0)) {
            if (newValue.code.length == 0) revert RegistryNotContract();
            if (!IReleaseRegistry(newValue).isTrustedRoot(activeRoot)) revert ActiveRootNotTrusted();

            UpgradeProposal memory p = pendingUpgrade;
            if (p.root != bytes32(0)) {
                if (!IReleaseRegistry(newValue).isTrustedRoot(p.root)) revert PendingRootNotTrusted();
            }

            CompatibilityState memory compat = compatibilityState;
            if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                if (!IReleaseRegistry(newValue).isTrustedRoot(compat.root)) revert CompatRootNotTrusted();
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
        if (releaseRegistryLocked) revert ReleaseRegistryPointerLocked();
        address registry = releaseRegistry;
        if (registry == address(0)) revert NoReleaseRegistry();
        releaseRegistryLocked = true;
        emit ReleaseRegistryLocked(registry);
    }

    function setExpectedComponentId(bytes32 newValue) external onlyRootAuthority {
        if (expectedComponentIdLocked) revert ExpectedComponentLocked();

        if (newValue != bytes32(0)) {
            address registry = releaseRegistry;
            if (registry == address(0)) revert NoReleaseRegistry();

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
        if (expectedComponentIdLocked) revert ExpectedComponentLocked();
        bytes32 componentId = expectedComponentId;
        if (componentId == bytes32(0)) revert ZeroComponentId();
        expectedComponentIdLocked = true;
        emit ExpectedComponentIdLocked(componentId);
    }

    function startReporterAuthorityTransfer(address newValue) external onlyRootAuthority {
        if (newValue == address(0)) revert ZeroReporterAuthority();
        unchecked {
            reporterAuthorityTransferNonce += 1;
        }
        pendingReporterAuthority = newValue;
        emit ReporterAuthorityTransferStarted(reporterAuthority, newValue);
    }

    function cancelReporterAuthorityTransfer() external onlyRootAuthority {
        address pendingValue = pendingReporterAuthority;
        if (pendingValue == address(0)) revert NoPendingReporterAuthority();
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityTransferCanceled(reporterAuthority, pendingValue);
    }

    function acceptReporterAuthority() external {
        address pendingValue = pendingReporterAuthority;
        if (pendingValue == address(0)) revert NoPendingReporterAuthority();
        if (msg.sender != pendingValue) revert NotPendingReporterAuthority();
        address previousValue = reporterAuthority;
        reporterAuthority = pendingValue;
        pendingReporterAuthority = address(0);
        emit ReporterAuthorityChanged(previousValue, pendingValue);
    }

    function acceptReporterAuthorityAuthorized(address expectedNewAuthority, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert Expired();

        address pendingValue = pendingReporterAuthority;
        if (pendingValue == address(0)) revert NoPendingReporterAuthority();
        if (pendingValue != expectedNewAuthority) revert PendingAuthorityMismatch();

        bytes32 digest = _hashAcceptAuthority(
            ROLE_REPORTER_AUTHORITY, expectedNewAuthority, reporterAuthorityTransferNonce, deadline
        );
        if (!_isValidSignatureNow(pendingValue, digest, signature)) revert InvalidPendingAuthoritySignature();
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
        if (minUpgradeDelayLocked) revert DelayLocked();
        if (newValue > MAX_UPGRADE_DELAY_SEC) revert DelayTooLarge();
        uint64 previousValue = minUpgradeDelaySec;
        minUpgradeDelaySec = newValue;
        emit MinUpgradeDelayChanged(previousValue, newValue);
    }

    function lockMinUpgradeDelay() external onlyRootAuthority {
        if (minUpgradeDelayLocked) revert DelayLocked();
        if (minUpgradeDelaySec == 0) revert DelayZero();
        minUpgradeDelayLocked = true;
        emit MinUpgradeDelayLocked(minUpgradeDelaySec);
    }

    function lockEmergencyCanUnpause() external onlyRootAuthority {
        if (emergencyCanUnpauseLocked) revert EmergencyUnpausePolicyIsLocked();
        emergencyCanUnpauseLocked = true;
        emit EmergencyUnpausePolicyLocked(emergencyCanUnpause);
    }

    function setEmergencyCanUnpause(bool newValue) external onlyRootAuthority {
        if (emergencyCanUnpauseLocked) revert EmergencyUnpausePolicyIsLocked();
        bool previousValue = emergencyCanUnpause;
        emergencyCanUnpause = newValue;
        emit EmergencyUnpausePolicyChanged(previousValue, newValue);
    }

    function setCompatibilityWindowSec(uint64 newValue) external onlyRootAuthority {
        if (compatibilityWindowLocked) revert WindowLocked();
        if (newValue > MAX_COMPATIBILITY_WINDOW_SEC) revert WindowTooLarge();
        uint64 previousValue = compatibilityWindowSec;
        compatibilityWindowSec = newValue;
        emit CompatibilityWindowChanged(previousValue, newValue);
    }

    function lockCompatibilityWindow() external onlyRootAuthority {
        if (compatibilityWindowLocked) revert WindowLocked();
        compatibilityWindowLocked = true;
        emit CompatibilityWindowLocked(compatibilityWindowSec);
    }

    function clearCompatibilityState() external onlyRootAuthority {
        CompatibilityState memory compat = compatibilityState;
        if (compat.root == bytes32(0)) revert NoCompatibilityState();
        delete compatibilityState;
        emit CompatibilityStateCleared(compat.root, compat.uriHash, compat.policyHash);
    }

    /// @notice Break-glass rollback to the stored compatibility state (if still valid).
    /// @dev This bypasses timelock/TTL because it rolls back to the last known-good state captured by the controller.
    function rollbackToCompatibilityState() external onlyRootAuthority {
        CompatibilityState memory compat = compatibilityState;
        // slither-disable-next-line incorrect-equality
        if (compat.root == bytes32(0)) revert NoCompatibilityState();
        if (block.timestamp > compat.until) revert CompatibilityExpired();
        _rollbackToCompatibility(compat);
    }

    function rollbackToCompatibilityStateAuthorized(uint256 deadline, bytes calldata signature) external {
        if (block.timestamp > deadline) revert Expired();

        CompatibilityState memory compat = compatibilityState;
        // slither-disable-next-line incorrect-equality
        if (compat.root == bytes32(0)) revert NoCompatibilityState();
        if (block.timestamp > compat.until) revert CompatibilityExpired();

        bytes32 structHash = keccak256(
            abi.encode(
                ROLLBACK_COMPATIBILITY_TYPEHASH,
                compat.root,
                compat.uriHash,
                compat.policyHash,
                compat.until,
                rollbackNonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        if (!_isValidSignatureNow(rootAuthority, digest, signature)) revert InvalidRootSignature();
        emit AuthoritySignatureConsumed(rootAuthority, digest, msg.sender);

        _rollbackToCompatibility(compat);
    }

    function _rollbackToCompatibility(CompatibilityState memory compat) private {
        address registry = releaseRegistry;
        if (registry != address(0)) {
            if (!IReleaseRegistry(registry).isTrustedRoot(compat.root)) revert RootNotTrusted();
        }

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            if (registry == address(0)) revert NoReleaseRegistry();
            _requireRootComponent(registry, compat.root, expected);
        }

        unchecked {
            rollbackNonce += 1;
        }

        bytes32 previousRoot = activeRoot;
        activeRoot = compat.root;
        activeUriHash = compat.uriHash;
        activePolicyHash = compat.policyHash;

        delete compatibilityState;
        emit CompatibilityStateCleared(compat.root, compat.uriHash, compat.policyHash);

        lastUpgradeAt = uint64(block.timestamp);
        emit RolledBackToCompatibility(previousRoot, activeRoot, activeUriHash, activePolicyHash);
    }

    function setAttestation(bytes32 key, bytes32 value) external onlyRootAuthority {
        if (key == bytes32(0)) revert KeyZero();
        if (attestationLocked[key]) revert AttestationKeyIsLocked();

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);
    }

    function setAttestationExpected(bytes32 key, bytes32 expectedPrevious, bytes32 value) external onlyRootAuthority {
        if (key == bytes32(0)) revert KeyZero();
        if (attestationLocked[key]) revert AttestationKeyIsLocked();
        if (attestations[key] != expectedPrevious) revert AttestationMismatch();

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);
    }

    function clearAttestation(bytes32 key) external onlyRootAuthority {
        if (key == bytes32(0)) revert KeyZero();
        if (attestationLocked[key]) revert AttestationKeyIsLocked();
        bytes32 previousValue = attestations[key];
        if (previousValue == bytes32(0)) revert AttestationAlreadyCleared();

        attestations[key] = bytes32(0);
        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, bytes32(0), at);
    }

    function setAttestationAndLock(bytes32 key, bytes32 value) external onlyRootAuthority {
        if (key == bytes32(0)) revert KeyZero();
        if (value == bytes32(0)) revert ValueZero();
        if (attestationLocked[key]) revert AttestationKeyIsLocked();

        bytes32 previousValue = attestations[key];
        attestations[key] = value;

        uint64 at = uint64(block.timestamp);
        attestationUpdatedAt[key] = at;
        emit AttestationSet(key, previousValue, value, at);

        attestationLocked[key] = true;
        emit AttestationLocked(key, value, at);
    }

    function lockAttestationKey(bytes32 key) external onlyRootAuthority {
        if (key == bytes32(0)) revert KeyZero();
        if (attestationLocked[key]) revert AttestationKeyIsLocked();

        bytes32 value = attestations[key];
        if (value == bytes32(0)) revert NoAttestation();

        uint64 at = uint64(block.timestamp);
        attestationLocked[key] = true;
        emit AttestationLocked(key, value, at);
    }

    function setAutoPauseOnBadCheckIn(bool newValue) external onlyRootAuthority {
        if (autoPauseOnBadCheckInLocked) revert AutoPauseLocked();
        bool previousValue = autoPauseOnBadCheckIn;
        autoPauseOnBadCheckIn = newValue;
        emit AutoPauseOnBadCheckInChanged(previousValue, newValue);
    }

    function lockAutoPauseOnBadCheckIn() external onlyRootAuthority {
        if (autoPauseOnBadCheckInLocked) revert AutoPauseLocked();
        autoPauseOnBadCheckInLocked = true;
        emit AutoPauseOnBadCheckInLocked(autoPauseOnBadCheckIn);
    }

    function setMaxCheckInAgeSec(uint64 newValue) external onlyRootAuthority {
        if (maxCheckInAgeLocked) revert CheckInAgeLocked();
        if (newValue > MAX_CHECKIN_AGE_SEC) revert CheckInAgeTooLarge();
        uint64 previousValue = maxCheckInAgeSec;
        maxCheckInAgeSec = newValue;
        emit MaxCheckInAgeChanged(previousValue, newValue);
    }

    function lockMaxCheckInAgeSec() external onlyRootAuthority {
        if (maxCheckInAgeLocked) revert CheckInAgeLocked();
        if (maxCheckInAgeSec == 0) revert CheckInAgeZero();
        maxCheckInAgeLocked = true;
        emit MaxCheckInAgeLocked(maxCheckInAgeSec);
    }

    /// @notice One-shot helper to lock down the controller for production.
    /// @dev Sets and locks multiple “knobs” in a single transaction (if not already locked).
    function finalizeProduction(
        address releaseRegistry_,
        bytes32 expectedComponentId_,
        uint64 minUpgradeDelaySec_,
        uint64 maxCheckInAgeSec_,
        bool autoPauseOnBadCheckIn_,
        uint64 compatibilityWindowSec_,
        bool emergencyCanUnpause_
    ) external onlyRootAuthority {
        if (releaseRegistryLocked && releaseRegistry != releaseRegistry_) {
            revert FinalizeMismatch();
        }
        if (expectedComponentIdLocked && expectedComponentId != expectedComponentId_) revert FinalizeMismatch();
        if (minUpgradeDelayLocked && minUpgradeDelaySec != minUpgradeDelaySec_) revert FinalizeMismatch();
        if (maxCheckInAgeLocked && maxCheckInAgeSec != maxCheckInAgeSec_) revert FinalizeMismatch();
        if (autoPauseOnBadCheckInLocked && autoPauseOnBadCheckIn != autoPauseOnBadCheckIn_) revert FinalizeMismatch();
        if (compatibilityWindowLocked && compatibilityWindowSec != compatibilityWindowSec_) revert FinalizeMismatch();
        if (emergencyCanUnpauseLocked && emergencyCanUnpause != emergencyCanUnpause_) revert FinalizeMismatch();

        if (!releaseRegistryLocked && releaseRegistry != releaseRegistry_) {
            if (releaseRegistry_ == address(0)) {
                if (expectedComponentId != bytes32(0)) revert ExpectedComponentSet();
            } else {
                if (releaseRegistry_.code.length == 0) revert RegistryNotContract();
                if (!IReleaseRegistry(releaseRegistry_).isTrustedRoot(activeRoot)) revert ActiveRootNotTrusted();

                UpgradeProposal memory p = pendingUpgrade;
                if (p.root != bytes32(0)) {
                    if (!IReleaseRegistry(releaseRegistry_).isTrustedRoot(p.root)) revert PendingRootNotTrusted();
                }

                CompatibilityState memory compat = compatibilityState;
                if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                    if (!IReleaseRegistry(releaseRegistry_).isTrustedRoot(compat.root)) revert CompatRootNotTrusted();
                }

                bytes32 expected = expectedComponentId;
                if (expected != bytes32(0)) {
                    _requireRootComponent(releaseRegistry_, activeRoot, expected);
                    if (p.root != bytes32(0)) {
                        _requireRootComponent(releaseRegistry_, p.root, expected);
                    }
                    if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                        _requireRootComponent(releaseRegistry_, compat.root, expected);
                    }
                }
            }

            address previousValue = releaseRegistry;
            releaseRegistry = releaseRegistry_;
            emit ReleaseRegistryChanged(previousValue, releaseRegistry_);
        }

        if (!expectedComponentIdLocked && expectedComponentId != expectedComponentId_) {
            if (expectedComponentId_ != bytes32(0)) {
                address registry = releaseRegistry;
                if (registry == address(0)) revert NoReleaseRegistry();

                _requireRootComponent(registry, activeRoot, expectedComponentId_);

                UpgradeProposal memory p = pendingUpgrade;
                if (p.root != bytes32(0)) {
                    _requireRootComponent(registry, p.root, expectedComponentId_);
                }

                CompatibilityState memory compat = compatibilityState;
                if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
                    _requireRootComponent(registry, compat.root, expectedComponentId_);
                }
            }

            bytes32 previousValue = expectedComponentId;
            expectedComponentId = expectedComponentId_;
            emit ExpectedComponentIdChanged(previousValue, expectedComponentId_);
        }

        if (!minUpgradeDelayLocked && minUpgradeDelaySec != minUpgradeDelaySec_) {
            if (minUpgradeDelaySec_ > MAX_UPGRADE_DELAY_SEC) revert DelayTooLarge();
            uint64 previousValue = minUpgradeDelaySec;
            minUpgradeDelaySec = minUpgradeDelaySec_;
            emit MinUpgradeDelayChanged(previousValue, minUpgradeDelaySec_);
        }

        if (!maxCheckInAgeLocked && maxCheckInAgeSec != maxCheckInAgeSec_) {
            if (maxCheckInAgeSec_ > MAX_CHECKIN_AGE_SEC) revert CheckInAgeTooLarge();
            uint64 previousValue = maxCheckInAgeSec;
            maxCheckInAgeSec = maxCheckInAgeSec_;
            emit MaxCheckInAgeChanged(previousValue, maxCheckInAgeSec_);
        }

        if (!autoPauseOnBadCheckInLocked && autoPauseOnBadCheckIn != autoPauseOnBadCheckIn_) {
            bool previousValue = autoPauseOnBadCheckIn;
            autoPauseOnBadCheckIn = autoPauseOnBadCheckIn_;
            emit AutoPauseOnBadCheckInChanged(previousValue, autoPauseOnBadCheckIn_);
        }

        if (!compatibilityWindowLocked && compatibilityWindowSec != compatibilityWindowSec_) {
            if (compatibilityWindowSec_ > MAX_COMPATIBILITY_WINDOW_SEC) revert WindowTooLarge();
            uint64 previousValue = compatibilityWindowSec;
            compatibilityWindowSec = compatibilityWindowSec_;
            emit CompatibilityWindowChanged(previousValue, compatibilityWindowSec_);
        }

        if (!emergencyCanUnpauseLocked && emergencyCanUnpause != emergencyCanUnpause_) {
            bool previousValue = emergencyCanUnpause;
            emergencyCanUnpause = emergencyCanUnpause_;
            emit EmergencyUnpausePolicyChanged(previousValue, emergencyCanUnpause_);
        }

        if (!releaseRegistryLocked) {
            address registry = releaseRegistry;
            if (registry == address(0)) revert NoReleaseRegistry();
            releaseRegistryLocked = true;
            emit ReleaseRegistryLocked(registry);
        }

        if (!expectedComponentIdLocked) {
            bytes32 componentId = expectedComponentId;
            if (componentId == bytes32(0)) revert ZeroComponentId();
            expectedComponentIdLocked = true;
            emit ExpectedComponentIdLocked(componentId);
        }

        if (!minUpgradeDelayLocked) {
            if (minUpgradeDelaySec == 0) revert DelayZero();
            minUpgradeDelayLocked = true;
            emit MinUpgradeDelayLocked(minUpgradeDelaySec);
        }

        if (!maxCheckInAgeLocked) {
            if (maxCheckInAgeSec == 0) revert CheckInAgeZero();
            maxCheckInAgeLocked = true;
            emit MaxCheckInAgeLocked(maxCheckInAgeSec);
        }

        if (!autoPauseOnBadCheckInLocked) {
            autoPauseOnBadCheckInLocked = true;
            emit AutoPauseOnBadCheckInLocked(autoPauseOnBadCheckIn);
        }

        if (!compatibilityWindowLocked) {
            compatibilityWindowLocked = true;
            emit CompatibilityWindowLocked(compatibilityWindowSec);
        }

        if (!emergencyCanUnpauseLocked) {
            emergencyCanUnpauseLocked = true;
            emit EmergencyUnpausePolicyLocked(emergencyCanUnpause);
        }
    }

    function isAcceptedState(bytes32 observedRoot, bytes32 observedUriHash, bytes32 observedPolicyHash)
        public
        view
        returns (bool)
    {
        // slither-disable-next-line incorrect-equality
        if (observedRoot == activeRoot && observedUriHash == activeUriHash && observedPolicyHash == activePolicyHash) {
            return _isRootTrusted(observedRoot);
        }

        CompatibilityState memory compat = compatibilityState;
        if (compat.root != bytes32(0) && block.timestamp <= compat.until) {
            if (
                // slither-disable-next-line incorrect-equality
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
        unchecked {
            reporterNonce += 1;
        }
        _checkIn(msg.sender, observedRoot, observedUriHash, observedPolicyHash);
    }

    function checkInAuthorized(
        bytes32 observedRoot,
        bytes32 observedUriHash,
        bytes32 observedPolicyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert Expired();
        address reporter = reporterAuthority;
        if (reporter == address(0)) revert ReporterNotSet();

        bytes32 structHash = keccak256(
            abi.encode(CHECKIN_TYPEHASH, observedRoot, observedUriHash, observedPolicyHash, reporterNonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        if (!_isValidSignatureNow(reporter, digest, signature)) revert InvalidReporterSignature();
        emit AuthoritySignatureConsumed(reporter, digest, msg.sender);

        unchecked {
            reporterNonce += 1;
        }
        _checkIn(reporter, observedRoot, observedUriHash, observedPolicyHash);
    }

    /// @notice Permissionless safety: pauses the controller if check-ins are stale beyond `maxCheckInAgeSec`.
    /// @dev Intended to be called by monitoring bots; no-op if disabled (`maxCheckInAgeSec==0`) or already paused.
    function pauseIfStale() external returns (bool) {
        if (paused) {
            return false;
        }

        uint64 maxAgeSec = maxCheckInAgeSec;
        if (maxAgeSec == 0) {
            return false;
        }

        uint64 base = lastCheckInAt;
        // slither-disable-next-line incorrect-equality
        if (base == 0) {
            base = genesisAt;
        }

        uint256 cutoff;
        unchecked {
            cutoff = uint256(base) + uint256(maxAgeSec);
        }
        if (block.timestamp <= cutoff) {
            return false;
        }

        _recordIncident(msg.sender, INCIDENT_STALE_CHECKIN);
        _setPaused(msg.sender, true);
        return true;
    }

    /// @notice Permissionless safety: pauses the controller if `activeRoot` is no longer trusted by `ReleaseRegistry`.
    /// @dev No-op if `releaseRegistry==0` or already paused. Treats registry call failure as untrusted.
    function pauseIfActiveRootUntrusted() external returns (bool) {
        if (paused) {
            return false;
        }

        if (releaseRegistry == address(0)) {
            return false;
        }

        if (_isRootTrusted(activeRoot)) {
            return false;
        }

        _recordIncident(msg.sender, INCIDENT_ACTIVE_ROOT_UNTRUSTED);
        _setPaused(msg.sender, true);
        return true;
    }

    function reportIncident(bytes32 incidentHash) external {
        if (incidentHash == bytes32(0)) revert IncidentHashZero();
        if (msg.sender != rootAuthority && msg.sender != emergencyAuthority && msg.sender != reporterAuthority) {
            revert NotIncidentReporter();
        }

        unchecked {
            incidentNonce += 1;
        }
        _reportIncident(msg.sender, incidentHash);
    }

    function reportIncidentAuthorized(bytes32 incidentHash, uint256 deadline, bytes calldata signature) external {
        if (block.timestamp > deadline) revert Expired();
        if (incidentHash == bytes32(0)) revert IncidentHashZero();

        bytes32 structHash = keccak256(abi.encode(REPORT_INCIDENT_TYPEHASH, incidentHash, incidentNonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        address authority = _resolveIncidentSigner(digest, signature);
        if (authority == address(0)) revert InvalidIncidentSignature();
        emit AuthoritySignatureConsumed(authority, digest, msg.sender);

        unchecked {
            incidentNonce += 1;
        }
        _reportIncident(authority, incidentHash);
    }

    function proposeUpgrade(bytes32 root, bytes32 uriHash, bytes32 policyHash, uint64 ttlSec)
        external
        onlyUpgradeAuthority
    {
        if (root == bytes32(0)) revert RootZero();
        if (ttlSec == 0) revert TtlZero();
        if (ttlSec > MAX_UPGRADE_TTL_SEC) revert TtlTooLarge();

        address registry = releaseRegistry;
        if (registry != address(0)) {
            if (!IReleaseRegistry(registry).isTrustedRoot(root)) revert RootNotTrusted();
        }

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            if (registry == address(0)) revert NoReleaseRegistry();
            _requireRootComponent(registry, root, expected);
        }

        unchecked {
            pendingUpgradeNonce += 1;
        }
        uint256 proposalNonce = pendingUpgradeNonce;

        pendingUpgrade = UpgradeProposal({
            root: root, uriHash: uriHash, policyHash: policyHash, createdAt: uint64(block.timestamp), ttlSec: ttlSec
        });

        emit UpgradeProposed(root, uriHash, policyHash, ttlSec, proposalNonce);
    }

    function proposeUpgradeByRelease(bytes32 componentId, uint64 version, bytes32 policyHash, uint64 ttlSec)
        external
        onlyUpgradeAuthority
    {
        if (componentId == bytes32(0)) revert ZeroComponentId();
        if (version == 0) revert VersionZero();
        if (ttlSec == 0) revert TtlZero();
        if (ttlSec > MAX_UPGRADE_TTL_SEC) revert TtlTooLarge();

        address registry = releaseRegistry;
        if (registry == address(0)) revert NoReleaseRegistry();

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            if (componentId != expected) revert ComponentMismatch();
        }

        try IReleaseRegistryGet(registry).get(componentId, version) returns (IReleaseRegistryGet.Release memory rel) {
            if (rel.root == bytes32(0)) revert ReleaseNotFound();
            if (!IReleaseRegistry(registry).isTrustedRoot(rel.root)) revert RootNotTrusted();

            unchecked {
                pendingUpgradeNonce += 1;
            }
            uint256 proposalNonce = pendingUpgradeNonce;

            pendingUpgrade = UpgradeProposal({
                root: rel.root,
                uriHash: rel.uriHash,
                policyHash: policyHash,
                createdAt: uint64(block.timestamp),
                ttlSec: ttlSec
            });

            emit UpgradeProposed(rel.root, rel.uriHash, policyHash, ttlSec, proposalNonce);
        } catch {
            revert RegistryMissingGet();
        }
    }

    function cancelUpgrade() external onlyRootOrUpgradeAuthority {
        UpgradeProposal memory upgrade = pendingUpgrade;
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function cancelUpgradeExpected(bytes32 root, bytes32 uriHash, bytes32 policyHash)
        external
        onlyRootOrUpgradeAuthority
    {
        UpgradeProposal memory upgrade = pendingUpgrade;
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        if (upgrade.root != root || upgrade.uriHash != uriHash || upgrade.policyHash != policyHash) {
            revert PendingMismatch();
        }
        delete pendingUpgrade;
        emit UpgradeCanceled(msg.sender);
    }

    function cancelUpgradeAuthorized(
        bytes32 root,
        bytes32 uriHash,
        bytes32 policyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert Expired();

        UpgradeProposal memory upgrade = pendingUpgrade;
        // slither-disable-next-line incorrect-equality
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        if (upgrade.root != root || upgrade.uriHash != uriHash || upgrade.policyHash != policyHash) {
            revert PendingMismatch();
        }

        bytes32 structHash = keccak256(
            abi.encode(
                CANCEL_UPGRADE_TYPEHASH,
                root,
                uriHash,
                policyHash,
                pendingUpgradeNonce,
                upgrade.createdAt,
                upgrade.ttlSec,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        if (!_isValidSignatureNow(rootAuthority, digest, signature)) revert InvalidRootSignature();
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
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        if (upgrade.root != root || upgrade.uriHash != uriHash || upgrade.policyHash != policyHash) {
            revert PendingMismatch();
        }
        _activateUpgrade(upgrade);
    }

    function activateUpgradeAuthorized(
        bytes32 root,
        bytes32 uriHash,
        bytes32 policyHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert Expired();

        UpgradeProposal memory upgrade = pendingUpgrade;
        // slither-disable-next-line incorrect-equality
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        if (upgrade.root != root || upgrade.uriHash != uriHash || upgrade.policyHash != policyHash) {
            revert PendingMismatch();
        }

        bytes32 structHash = keccak256(
            abi.encode(
                ACTIVATE_UPGRADE_TYPEHASH,
                root,
                uriHash,
                policyHash,
                pendingUpgradeNonce,
                upgrade.createdAt,
                upgrade.ttlSec,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        if (!_isValidSignatureNow(rootAuthority, digest, signature)) revert InvalidRootSignature();
        emit AuthoritySignatureConsumed(rootAuthority, digest, msg.sender);

        _activateUpgrade(upgrade);
    }

    function _activateUpgrade(UpgradeProposal memory upgrade) private {
        // slither-disable-next-line incorrect-equality
        if (upgrade.root == bytes32(0)) revert NoPendingUpgrade();
        uint256 createdAt = uint256(upgrade.createdAt);
        uint256 timelockUntil;
        unchecked {
            timelockUntil = createdAt + uint256(minUpgradeDelaySec);
        }
        if (block.timestamp < timelockUntil) revert UpgradeTimelocked();

        uint256 expiresAt;
        unchecked {
            expiresAt = createdAt + uint256(upgrade.ttlSec);
        }
        if (block.timestamp > expiresAt) revert UpgradeExpired();

        address registry = releaseRegistry;
        if (registry != address(0)) {
            if (!IReleaseRegistry(registry).isTrustedRoot(upgrade.root)) revert RootNotTrusted();
        }

        bytes32 expected = expectedComponentId;
        if (expected != bytes32(0)) {
            if (registry == address(0)) revert NoReleaseRegistry();
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
            uint64 until;
            unchecked {
                until = uint64(block.timestamp + uint256(windowSec));
            }
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

        (bool ok, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(EIP1271_MAGICVALUE, digest, signature));
        // Casting to `bytes4` is safe because we check `ret.length >= 4` first.
        // slither-disable-start incorrect-equality
        // forge-lint: disable-next-line(unsafe-typecast)
        return ok && ret.length >= 4 && bytes4(ret) == EIP1271_MAGICVALUE;
        // slither-disable-end incorrect-equality
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
            // Return `address(0)` instead of reverting so multi-authority resolvers can keep trying other roles.
            return address(0);
        }
        if (v != 27 && v != 28) revert BadV();
        if (uint256(s) > SECP256K1N_HALF) revert BadS();

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert BadSignature();
        return recovered;
    }

    function _recordIncident(address by, bytes32 incidentHash) private {
        unchecked {
            incidentCount += 1;
        }
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
        } else {
            unchecked {
                pauseNonce += 1;
            }
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

        unchecked {
            pauseNonce += 1;
        }
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
        // slither-disable-next-line incorrect-equality
        if (root == bytes32(0)) revert RootZero();
        if (componentId == bytes32(0)) revert ZeroComponentId();

        // slither-disable-next-line unused-return
        try IReleaseRegistryByRoot(registry).getByRoot(root) returns (
            bytes32 foundComponentId, uint64, bytes32, bytes32, bool
        ) {
            // slither-disable-next-line incorrect-equality
            if (foundComponentId == bytes32(0)) revert RootUnknown();
            if (foundComponentId != componentId) revert ComponentMismatch();
        } catch {
            revert RegistryMissingGetByRoot();
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
        if (maxCheckInAgeLocked) {
            flags |= 128;
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
