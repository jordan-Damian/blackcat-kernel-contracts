/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";

contract TrustedRegistryNoByRoot {
    function isTrustedRoot(bytes32) external pure returns (bool) {
        return true;
    }
}

contract TrustedRegistryBadByRoot {
    function isTrustedRoot(bytes32) external pure returns (bool) {
        return true;
    }

    function getByRoot(bytes32)
        external
        pure
        returns (bytes32 componentId, uint64 version, bytes32 uriHash, bytes32 metaHash, bool revoked)
    {
        return (bytes32(0), 0, bytes32(0), bytes32(0), false);
    }
}

contract ToggleTrustedRegistry {
    bool public shouldRevert;
    mapping(bytes32 => bool) public trusted;

    function setTrusted(bytes32 root, bool v) external {
        trusted[root] = v;
    }

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function isTrustedRoot(bytes32 root) external view returns (bool) {
        if (shouldRevert) {
            revert("ToggleTrustedRegistry: boom");
        }
        return trusted[root];
    }
}

contract InstanceControllerAdditionalTest is TestBase {
    bytes32 private constant SET_PAUSED_TYPEHASH =
        keccak256("SetPaused(bool expectedPaused,bool newPaused,uint256 nonce,uint256 deadline)");
    bytes32 private constant CHECKIN_TYPEHASH = keccak256(
        "CheckIn(bytes32 observedRoot,bytes32 observedUriHash,bytes32 observedPolicyHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant REPORT_INCIDENT_TYPEHASH =
        keccak256("ReportIncident(bytes32 incidentHash,uint256 nonce,uint256 deadline)");

    bytes32 private constant COMPONENT_ID = keccak256("blackcat-core");

    InstanceFactory private factory;
    InstanceController private controller;

    address private root = address(0x1111111111111111111111111111111111111111);
    address private upgrader = address(0x2222222222222222222222222222222222222222);
    address private emergency = address(0x3333333333333333333333333333333333333333);
    address private reporter = address(0x4444444444444444444444444444444444444444);

    bytes32 private genesisRoot = keccak256("genesis-root");
    bytes32 private genesisUriHash = keccak256("uri");
    bytes32 private genesisPolicyHash = keccak256("policy");

    function setUp() public {
        factory = new InstanceFactory(address(0));
        address instance =
            factory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
        controller = InstanceController(instance);
    }

    function test_initialize_rejects_zero_upgrade_authority() public {
        InstanceFactory f = new InstanceFactory(address(0));
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroUpgradeAuthority.selector));
        f.createInstance(root, address(0), emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_initialize_rejects_zero_emergency_authority() public {
        InstanceFactory f = new InstanceFactory(address(0));
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroEmergencyAuthority.selector));
        f.createInstance(root, upgrader, address(0), genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_initialize_rejects_zero_genesis_root() public {
        InstanceFactory f = new InstanceFactory(address(0));
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ZeroGenesisRoot.selector));
        f.createInstance(root, upgrader, emergency, bytes32(0), genesisUriHash, genesisPolicyHash);
    }

    function test_setPausedAuthorized_rejects_expired() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.Expired.selector));
        controller.setPausedAuthorized(false, true, block.timestamp - 1, bytes("x"));
    }

    function test_setPausedAuthorized_rejects_noop() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoOp.selector));
        controller.setPausedAuthorized(false, false, block.timestamp + 3600, bytes("x"));
    }

    function test_setPausedAuthorized_rejects_invalid_signature() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.InvalidPauseSignature.selector));
        controller.setPausedAuthorized(false, true, block.timestamp + 3600, bytes("x"));
    }

    function test_setMaxCheckInAgeSec_rejects_too_large() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.CheckInAgeTooLarge.selector));
        controller.setMaxCheckInAgeSec(uint64(30 days) + 1);
    }

    function test_lockMaxCheckInAgeSec_rejects_when_zero() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.CheckInAgeZero.selector));
        controller.lockMaxCheckInAgeSec();
    }

    function test_lockMaxCheckInAgeSec_locks_and_blocks_changes() public {
        vm.prank(root);
        controller.setMaxCheckInAgeSec(10);

        vm.prank(root);
        controller.lockMaxCheckInAgeSec();
        assertTrue(controller.maxCheckInAgeLocked(), "maxCheckInAgeLocked should be true");

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.CheckInAgeLocked.selector));
        controller.setMaxCheckInAgeSec(5);

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.CheckInAgeLocked.selector));
        controller.lockMaxCheckInAgeSec();
    }

    function test_cancelRootAuthorityTransfer_reverts_without_pending() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoPendingRootAuthority.selector));
        controller.cancelRootAuthorityTransfer();
    }

    function test_cancelRootAuthorityTransfer_clears_pending() public {
        address newRoot = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startRootAuthorityTransfer(newRoot);
        assertEq(controller.pendingRootAuthority(), newRoot, "pendingRootAuthority mismatch");

        vm.prank(root);
        controller.cancelRootAuthorityTransfer();
        assertEq(controller.pendingRootAuthority(), address(0), "pendingRootAuthority should be cleared");
    }

    function test_cancelUpgradeAuthorityTransfer_reverts_without_pending() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoPendingUpgradeAuthority.selector));
        controller.cancelUpgradeAuthorityTransfer();
    }

    function test_cancelUpgradeAuthorityTransfer_clears_pending() public {
        address newUpgrade = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startUpgradeAuthorityTransfer(newUpgrade);
        assertEq(controller.pendingUpgradeAuthority(), newUpgrade, "pendingUpgradeAuthority mismatch");

        vm.prank(root);
        controller.cancelUpgradeAuthorityTransfer();
        assertEq(controller.pendingUpgradeAuthority(), address(0), "pendingUpgradeAuthority should be cleared");
    }

    function test_cancelEmergencyAuthorityTransfer_reverts_without_pending() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoPendingEmergencyAuthority.selector));
        controller.cancelEmergencyAuthorityTransfer();
    }

    function test_cancelEmergencyAuthorityTransfer_clears_pending() public {
        address newEmergency = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startEmergencyAuthorityTransfer(newEmergency);
        assertEq(controller.pendingEmergencyAuthority(), newEmergency, "pendingEmergencyAuthority mismatch");

        vm.prank(root);
        controller.cancelEmergencyAuthorityTransfer();
        assertEq(controller.pendingEmergencyAuthority(), address(0), "pendingEmergencyAuthority should be cleared");
    }

    function test_acceptEmergencyAuthority_direct_flow_and_rejects_wrong_sender() public {
        address newEmergency = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startEmergencyAuthorityTransfer(newEmergency);

        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NotPendingEmergencyAuthority.selector));
        controller.acceptEmergencyAuthority();

        vm.prank(newEmergency);
        controller.acceptEmergencyAuthority();
        assertEq(controller.emergencyAuthority(), newEmergency, "emergencyAuthority mismatch");
    }

    function test_cancelReporterAuthorityTransfer_reverts_without_pending() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoPendingReporterAuthority.selector));
        controller.cancelReporterAuthorityTransfer();
    }

    function test_cancelReporterAuthorityTransfer_clears_pending() public {
        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        assertEq(controller.pendingReporterAuthority(), reporter, "pendingReporterAuthority mismatch");

        vm.prank(root);
        controller.cancelReporterAuthorityTransfer();
        assertEq(controller.pendingReporterAuthority(), address(0), "pendingReporterAuthority should be cleared");
    }

    function test_clearReporterAuthority_clears_reporter_and_pending() public {
        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        vm.prank(reporter);
        controller.acceptReporterAuthority();
        assertEq(controller.reporterAuthority(), reporter, "reporterAuthority mismatch");

        vm.prank(root);
        controller.startReporterAuthorityTransfer(address(0x9999999999999999999999999999999999999999));
        assertTrue(controller.pendingReporterAuthority() != address(0), "pendingReporterAuthority should be set");

        vm.prank(root);
        controller.clearReporterAuthority();

        assertEq(controller.reporterAuthority(), address(0), "reporterAuthority should be cleared");
        assertEq(controller.pendingReporterAuthority(), address(0), "pendingReporterAuthority should be cleared");
    }

    function test_checkIn_rejects_when_reporter_not_set() public {
        vm.prank(reporter);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NotReporterAuthority.selector));
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_checkInAuthorized_rejects_when_reporter_not_set() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ReporterNotSet.selector));
        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, block.timestamp + 3600, bytes("x"));
    }

    function test_checkInAuthorized_rejects_expired() public {
        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.expectRevert(abi.encodeWithSelector(InstanceController.Expired.selector));
        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, block.timestamp - 1, bytes("x"));
    }

    function test_checkInAuthorized_rejects_invalid_signature() public {
        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.expectRevert(abi.encodeWithSelector(InstanceController.InvalidReporterSignature.selector));
        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, block.timestamp + 3600, bytes("x"));
    }

    function test_checkIn_while_paused_marks_not_ok_and_does_not_raise_incident() public {
        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(root);
        controller.setAutoPauseOnBadCheckIn(true);

        vm.prank(emergency);
        controller.pause();

        vm.prank(reporter);
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);

        assertTrue(controller.paused(), "should remain paused");
        assertTrue(!controller.lastCheckInOk(), "paused check-in should be not ok");
        assertEq(uint256(controller.incidentCount()), 0, "incidentCount should not change while paused");
    }

    function test_reportIncident_rejects_zero_hash() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.IncidentHashZero.selector));
        controller.reportIncident(bytes32(0));
    }

    function test_reportIncident_rejects_unauthorized_sender() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NotIncidentReporter.selector));
        controller.reportIncident(keccak256("incident"));
    }

    function test_reportIncidentAuthorized_rejects_expired() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.Expired.selector));
        controller.reportIncidentAuthorized(keccak256("incident"), block.timestamp - 1, bytes("x"));
    }

    function test_reportIncidentAuthorized_rejects_zero_hash() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.IncidentHashZero.selector));
        controller.reportIncidentAuthorized(bytes32(0), block.timestamp + 3600, bytes("x"));
    }

    function test_reportIncidentAuthorized_rejects_invalid_signature() public {
        vm.expectRevert(abi.encodeWithSelector(InstanceController.InvalidIncidentSignature.selector));
        controller.reportIncidentAuthorized(keccak256("incident"), block.timestamp + 3600, bytes("x"));
    }

    function test_reportIncidentAuthorized_while_paused_increments_pauseNonce() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);
        uint256 emergencyPk = 0xB0B;
        address emergencyAddr = vm.addr(emergencyPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergencyAddr, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(rootAddr);
        c.pause();

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = _digestReportIncident(c, keccak256("incident-paused"), deadline);
        bytes memory sig = _sign(rootPk, digest);

        uint256 pauseNonceBefore = c.pauseNonce();
        assertTrue(c.paused(), "should be paused");

        c.reportIncidentAuthorized(keccak256("incident-paused"), deadline, sig);

        assertEq(c.pauseNonce(), pauseNonceBefore + 1, "pauseNonce should increment while paused");
        assertTrue(c.paused(), "should remain paused");
    }

    function test_setReleaseRegistry_rejects_non_contract() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.RegistryNotContract.selector));
        controller.setReleaseRegistry(address(1));
    }

    function test_setReleaseRegistry_rejects_active_root_not_trusted() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ActiveRootNotTrusted.selector));
        controller.setReleaseRegistry(address(registry));
    }

    function test_setReleaseRegistry_rejects_pending_root_not_trusted() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        registry.publish(COMPONENT_ID, 1, genesisRoot, genesisUriHash, 0);

        bytes32 nextRoot = keccak256("pending-root-not-trusted");
        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, keccak256("uri2"), keccak256("policy2"), 3600);

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.PendingRootNotTrusted.selector));
        controller.setReleaseRegistry(address(registry));
    }

    function test_setReleaseRegistry_rejects_compat_root_not_trusted() public {
        vm.prank(root);
        controller.setCompatibilityWindowSec(3600);

        bytes32 nextRoot = keccak256("compat-next-root");
        bytes32 nextUriHash = keccak256("compat-next-uri");
        bytes32 nextPolicyHash = keccak256("compat-next-policy");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        vm.prank(root);
        controller.activateUpgrade();

        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        // Only publish the *active* root, not the compatibility root.
        registry.publish(COMPONENT_ID, 1, nextRoot, nextUriHash, 0);

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.CompatRootNotTrusted.selector));
        controller.setReleaseRegistry(address(registry));
    }

    function test_setReleaseRegistry_rejects_zero_when_expected_component_is_set() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        registry.publish(COMPONENT_ID, 1, genesisRoot, genesisUriHash, 0);

        vm.prank(root);
        controller.setReleaseRegistry(address(registry));

        vm.prank(root);
        controller.setExpectedComponentId(COMPONENT_ID);

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.ExpectedComponentSet.selector));
        controller.setReleaseRegistry(address(0));
    }

    function test_finalizeProduction_rejects_registry_missing_getByRoot() public {
        TrustedRegistryNoByRoot registry = new TrustedRegistryNoByRoot();

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.RegistryMissingGetByRoot.selector));
        controller.finalizeProduction(address(registry), COMPONENT_ID, 1, 1, true, 0, false);
    }

    function test_finalizeProduction_rejects_root_unknown_if_registry_is_inconsistent() public {
        TrustedRegistryBadByRoot registry = new TrustedRegistryBadByRoot();

        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.RootUnknown.selector));
        controller.finalizeProduction(address(registry), COMPONENT_ID, 1, 1, true, 0, false);
    }

    function test_clearCompatibilityState_reverts_when_empty() public {
        vm.prank(root);
        vm.expectRevert(abi.encodeWithSelector(InstanceController.NoCompatibilityState.selector));
        controller.clearCompatibilityState();
    }

    function test_clearCompatibilityState_clears() public {
        vm.prank(root);
        controller.setCompatibilityWindowSec(3600);

        bytes32 nextRoot = keccak256("compat-next-root-2");
        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, genesisUriHash, genesisPolicyHash, 3600);

        vm.prank(root);
        controller.activateUpgrade();

        (bytes32 compatRoot,,,) = controller.compatibilityState();
        assertTrue(compatRoot != bytes32(0), "compatibilityState should exist");

        vm.prank(root);
        controller.clearCompatibilityState();

        (bytes32 cleared,,,) = controller.compatibilityState();
        assertEq(cleared, bytes32(0), "compatibilityState should be cleared");
    }

    function test_pauseIfStale_is_noop_when_disabled() public {
        bool didPause = controller.pauseIfStale();
        assertTrue(!didPause, "pauseIfStale should be disabled by default");
        assertTrue(!controller.paused(), "controller should remain unpaused");
    }

    function test_pauseIfActiveRootUntrusted_is_noop_without_registry() public {
        bool didPause = controller.pauseIfActiveRootUntrusted();
        assertTrue(!didPause, "pauseIfActiveRootUntrusted should no-op without registry");
    }

    function test_pauseIfActiveRootUntrusted_pauses_on_registry_call_failure() public {
        ToggleTrustedRegistry reg = new ToggleTrustedRegistry();
        reg.setTrusted(genesisRoot, true);

        vm.prank(root);
        controller.setReleaseRegistry(address(reg));

        reg.setShouldRevert(true);

        bool didPause = controller.pauseIfActiveRootUntrusted();
        assertTrue(didPause, "should pause when registry call fails");
        assertTrue(controller.paused(), "controller should be paused");
    }

    function test_snapshot_includes_paused_and_roots() public {
        vm.prank(emergency);
        controller.pause();

        (uint8 version, bool paused_, bytes32 activeRoot_, bytes32 activeUriHash_, bytes32 activePolicyHash_,,,,,,,) =
            controller.snapshot();

        assertEq(uint256(version), 1, "version mismatch");
        assertTrue(paused_, "paused flag mismatch");
        assertEq(activeRoot_, genesisRoot, "activeRoot mismatch");
        assertEq(activeUriHash_, genesisUriHash, "activeUriHash mismatch");
        assertEq(activePolicyHash_, genesisPolicyHash, "activePolicyHash mismatch");
    }

    function _hashTypedData(InstanceController c, bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", c.domainSeparator(), structHash));
    }

    function _digestReportIncident(InstanceController c, bytes32 incidentHash, uint256 deadline)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(REPORT_INCIDENT_TYPEHASH, incidentHash, c.incidentNonce(), deadline));
        return _hashTypedData(c, structHash);
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
