pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract InstanceControllerTest is TestBase {
    InstanceController private controller;
    InstanceFactory private factory;

    address private root = address(0x1111111111111111111111111111111111111111);
    address private upgrader = address(0x2222222222222222222222222222222222222222);
    address private emergency = address(0x3333333333333333333333333333333333333333);

    bytes32 private genesisRoot = keccak256("genesis-root");
    bytes32 private genesisUriHash = keccak256("uri");
    bytes32 private genesisPolicyHash = keccak256("policy");

    function setUp() public {
        factory = new InstanceFactory(address(0));
        address instance =
            factory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
        controller = InstanceController(instance);
    }

    function test_initialize_sets_state() public view {
        assertEq(controller.rootAuthority(), root, "rootAuthority mismatch");
        assertEq(controller.upgradeAuthority(), upgrader, "upgradeAuthority mismatch");
        assertEq(controller.emergencyAuthority(), emergency, "emergencyAuthority mismatch");
        assertEq(controller.releaseRegistry(), address(0), "releaseRegistry mismatch");
        assertEq(controller.activeRoot(), genesisRoot, "activeRoot mismatch");
        assertEq(controller.activeUriHash(), genesisUriHash, "activeUriHash mismatch");
        assertEq(controller.activePolicyHash(), genesisPolicyHash, "activePolicyHash mismatch");
        assertTrue(controller.paused() == false, "paused should be false");
    }

    function test_initialize_reverts_on_second_call() public {
        vm.expectRevert("InstanceController: already initialized");
        controller.initialize(root, upgrader, emergency, address(0), genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_initialize_rejects_zero_authorities_via_factory() public {
        vm.expectRevert("InstanceController: root=0");
        factory.createInstance(address(0), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_pause_unpause_access_control() public {
        vm.prank(emergency);
        controller.pause();
        assertTrue(controller.paused(), "pause failed");

        vm.prank(emergency);
        vm.expectRevert("InstanceController: emergency cannot unpause");
        controller.unpause();

        vm.prank(root);
        controller.unpause();
        assertTrue(controller.paused() == false, "root unpause failed");

        vm.prank(root);
        controller.pause();
        assertTrue(controller.paused(), "root pause failed");

        vm.prank(root);
        controller.unpause();
        assertTrue(controller.paused() == false, "root unpause failed");

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not emergency/root authority");
        controller.pause();
    }

    function test_emergency_unpause_can_be_enabled_by_root() public {
        vm.prank(emergency);
        controller.pause();
        assertTrue(controller.paused(), "pause failed");

        vm.prank(root);
        controller.setEmergencyCanUnpause(true);

        vm.prank(emergency);
        controller.unpause();
        assertTrue(controller.paused() == false, "emergency unpause failed after enabling");
    }

    function test_emergency_unpause_policy_lock_freezes_value() public {
        vm.prank(root);
        controller.setEmergencyCanUnpause(true);

        vm.prank(root);
        controller.lockEmergencyCanUnpause();

        vm.prank(root);
        vm.expectRevert("InstanceController: unpause policy locked");
        controller.setEmergencyCanUnpause(false);
    }

    function test_setPausedAuthorized_accepts_emergency_signature_and_is_not_replayable() public {
        uint256 emergencyPk = 0xBEEF;
        address emergencyAddr = vm.addr(emergencyPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(root, upgrader, emergencyAddr, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        assertTrue(!c.paused(), "should start unpaused");

        uint256 deadline = block.timestamp + 3600;
        bytes32 unpauseDigest = c.hashSetPaused(true, false, deadline);
        bytes memory unpauseSig = _sign(emergencyPk, unpauseDigest);

        bytes32 pauseDigest = c.hashSetPaused(false, true, deadline);
        bytes memory pauseSig = _sign(emergencyPk, pauseDigest);

        c.setPausedAuthorized(false, true, deadline, pauseSig);
        assertTrue(c.paused(), "should be paused");

        vm.expectRevert("InstanceController: invalid pause signature");
        c.setPausedAuthorized(true, false, deadline, unpauseSig);
    }

    function test_setPausedAuthorized_rejects_emergency_unpause_when_disabled() public {
        uint256 emergencyPk = 0xBEEF;
        address emergencyAddr = vm.addr(emergencyPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(root, upgrader, emergencyAddr, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        uint256 deadline = block.timestamp + 3600;
        bytes32 pauseDigest = c.hashSetPaused(false, true, deadline);
        bytes memory pauseSig = _sign(emergencyPk, pauseDigest);
        c.setPausedAuthorized(false, true, deadline, pauseSig);
        assertTrue(c.paused(), "should be paused");

        bytes32 unpauseDigest = c.hashSetPaused(true, false, deadline);
        bytes memory unpauseSig = _sign(emergencyPk, unpauseDigest);
        vm.expectRevert("InstanceController: emergency cannot unpause");
        c.setPausedAuthorized(true, false, deadline, unpauseSig);
    }

    function test_setPausedAuthorized_rejects_when_state_mismatch() public {
        uint256 emergencyPk = 0xBEEF;
        address emergencyAddr = vm.addr(emergencyPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(root, upgrader, emergencyAddr, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashSetPaused(true, false, deadline);
        bytes memory sig = _sign(emergencyPk, digest);

        vm.expectRevert("InstanceController: paused mismatch");
        c.setPausedAuthorized(true, false, deadline, sig);
    }

    function test_authority_rotation_only_root() public {
        address newRoot = address(0x4444444444444444444444444444444444444444);
        address newUpgrade = address(0x5555555555555555555555555555555555555555);

        vm.prank(root);
        controller.startRootAuthorityTransfer(newRoot);

        vm.prank(newRoot);
        controller.acceptRootAuthority();
        assertEq(controller.rootAuthority(), newRoot, "root authority not updated");

        vm.prank(newRoot);
        controller.startUpgradeAuthorityTransfer(newUpgrade);

        vm.prank(newUpgrade);
        controller.acceptUpgradeAuthority();
        assertEq(controller.upgradeAuthority(), newUpgrade, "upgrade authority not updated");

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not root authority");
        controller.startUpgradeAuthorityTransfer(address(0x6666666666666666666666666666666666666666));
    }

    function test_acceptRootAuthorityAuthorized_accepts_pending_signature_and_prevents_reuse() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        uint256 newRootPk = 0xB0B;
        address newRootAddr = vm.addr(newRootPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(rootAddr);
        c.startRootAuthorityTransfer(newRootAddr);
        assertEq(c.rootAuthorityTransferNonce(), 1, "root transfer nonce should increment");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashAcceptRootAuthority(newRootAddr, deadline);
        bytes memory sig = _sign(newRootPk, digest);

        c.acceptRootAuthorityAuthorized(newRootAddr, deadline, sig);
        assertEq(c.rootAuthority(), newRootAddr, "root authority not updated");

        vm.expectRevert("InstanceController: no pending root");
        c.acceptRootAuthorityAuthorized(newRootAddr, deadline, sig);
    }

    function test_acceptRootAuthorityAuthorized_rejects_stale_signature_after_restart() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        uint256 newRootPk = 0xB0B;
        address newRootAddr = vm.addr(newRootPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(rootAddr);
        c.startRootAuthorityTransfer(newRootAddr);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashAcceptRootAuthority(newRootAddr, deadline);
        bytes memory sig = _sign(newRootPk, digest);

        vm.prank(rootAddr);
        c.startRootAuthorityTransfer(newRootAddr);

        vm.expectRevert("InstanceController: invalid pending root signature");
        c.acceptRootAuthorityAuthorized(newRootAddr, deadline, sig);
    }

    function test_acceptUpgradeAuthorityAuthorized_accepts_pending_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        uint256 newUpgradePk = 0xB0B;
        address newUpgradeAddr = vm.addr(newUpgradePk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(rootAddr);
        c.startUpgradeAuthorityTransfer(newUpgradeAddr);
        assertEq(c.upgradeAuthorityTransferNonce(), 1, "upgrade transfer nonce should increment");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashAcceptUpgradeAuthority(newUpgradeAddr, deadline);
        bytes memory sig = _sign(newUpgradePk, digest);

        c.acceptUpgradeAuthorityAuthorized(newUpgradeAddr, deadline, sig);
        assertEq(c.upgradeAuthority(), newUpgradeAddr, "upgrade authority not updated");
    }

    function test_acceptEmergencyAuthorityAuthorized_accepts_pending_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        uint256 newEmergencyPk = 0xB0B;
        address newEmergencyAddr = vm.addr(newEmergencyPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(rootAddr);
        c.startEmergencyAuthorityTransfer(newEmergencyAddr);
        assertEq(c.emergencyAuthorityTransferNonce(), 1, "emergency transfer nonce should increment");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashAcceptEmergencyAuthority(newEmergencyAddr, deadline);
        bytes memory sig = _sign(newEmergencyPk, digest);

        c.acceptEmergencyAuthorityAuthorized(newEmergencyAddr, deadline, sig);
        assertEq(c.emergencyAuthority(), newEmergencyAddr, "emergency authority not updated");
    }

    function test_acceptReporterAuthorityAuthorized_accepts_pending_signature() public {
        uint256 reporterPk = 0xCAFE;
        address reporterAddr = vm.addr(reporterPk);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporterAddr);
        assertEq(controller.reporterAuthorityTransferNonce(), 1, "reporter transfer nonce should increment");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = controller.hashAcceptReporterAuthority(reporterAddr, deadline);
        bytes memory sig = _sign(reporterPk, digest);

        controller.acceptReporterAuthorityAuthorized(reporterAddr, deadline, sig);
        assertEq(controller.reporterAuthority(), reporterAddr, "reporter authority not updated");
    }

    function test_attestations_are_root_controlled() public {
        bytes32 key = keccak256("config.runtime.v1");
        bytes32 v1 = keccak256("v1");

        vm.prank(root);
        controller.setAttestation(key, v1);

        assertEq(controller.attestations(key), v1, "attestation value mismatch");
        assertTrue(controller.attestationUpdatedAt(key) != 0, "attestation updatedAt should be set");

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not root authority");
        controller.setAttestation(key, keccak256("v2"));
    }

    function test_attestation_lock_prevents_changes_and_clearing() public {
        bytes32 key = keccak256("config.runtime.v1");

        vm.prank(root);
        controller.setAttestation(key, keccak256("v1"));

        vm.prank(root);
        controller.lockAttestationKey(key);
        assertTrue(controller.attestationLocked(key), "attestation should be locked");

        vm.prank(root);
        vm.expectRevert("InstanceController: attestation locked");
        controller.setAttestation(key, keccak256("v2"));

        vm.prank(root);
        vm.expectRevert("InstanceController: attestation locked");
        controller.clearAttestation(key);
    }

    function test_lockAttestationKey_rejects_when_empty() public {
        bytes32 key = keccak256("config.runtime.v1");

        vm.prank(root);
        vm.expectRevert("InstanceController: no attestation");
        controller.lockAttestationKey(key);
    }

    function test_setAttestationAndLock_sets_and_locks() public {
        bytes32 key = keccak256("config.runtime.v1");
        bytes32 value = keccak256("v1");

        vm.prank(root);
        controller.setAttestationAndLock(key, value);

        assertEq(controller.attestations(key), value, "attestation value mismatch");
        assertTrue(controller.attestationLocked(key), "attestation should be locked");
        assertTrue(controller.attestationUpdatedAt(key) != 0, "updatedAt should be set");

        vm.prank(root);
        vm.expectRevert("InstanceController: attestation locked");
        controller.setAttestationExpected(key, value, keccak256("v2"));
    }

    function test_setAttestationExpected_rejects_mismatch() public {
        bytes32 key = keccak256("config.runtime.v1");

        vm.prank(root);
        controller.setAttestation(key, keccak256("v1"));

        vm.prank(root);
        vm.expectRevert("InstanceController: attestation mismatch");
        controller.setAttestationExpected(key, keccak256("wrong"), keccak256("v2"));
    }

    function test_clearAttestation_rejects_when_already_cleared() public {
        bytes32 key = keccak256("config.runtime.v1");

        vm.prank(root);
        controller.setAttestation(key, keccak256("v1"));

        vm.prank(root);
        controller.clearAttestation(key);

        vm.prank(root);
        vm.expectRevert("InstanceController: attestation already cleared");
        controller.clearAttestation(key);
    }

    function test_propose_and_activate_upgrade() public {
        bytes32 nextRoot = keccak256("next-root");
        bytes32 nextUriHash = keccak256("next-uri");
        bytes32 nextPolicyHash = keccak256("next-policy");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        (bytes32 pRoot, bytes32 pUri, bytes32 pPolicy, uint64 createdAt, uint64 ttlSec) = controller.pendingUpgrade();
        assertEq(pRoot, nextRoot, "pending root mismatch");
        assertEq(pUri, nextUriHash, "pending uri mismatch");
        assertEq(pPolicy, nextPolicyHash, "pending policy mismatch");
        assertTrue(createdAt != 0, "createdAt should be set");
        assertEq(uint256(ttlSec), 3600, "ttl mismatch");

        vm.prank(root);
        controller.activateUpgrade();

        assertEq(controller.activeRoot(), nextRoot, "active root not updated");
        assertEq(controller.activeUriHash(), nextUriHash, "active uri not updated");
        assertEq(controller.activePolicyHash(), nextPolicyHash, "active policy not updated");

        bytes32 clearedRoot;
        (clearedRoot,,,,) = controller.pendingUpgrade();
        assertEq(clearedRoot, bytes32(0), "pending upgrade not cleared");
    }

    function test_activateUpgradeExpected_rejects_mismatch() public {
        bytes32 nextRoot = keccak256("next-root-expected");
        bytes32 nextUriHash = keccak256("next-uri-expected");
        bytes32 nextPolicyHash = keccak256("next-policy-expected");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        vm.prank(root);
        vm.expectRevert("InstanceController: pending mismatch");
        controller.activateUpgradeExpected(nextRoot, nextUriHash, keccak256("wrong"));
    }

    function test_activateUpgradeAuthorized_accepts_eoa_root_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 nextRoot = keccak256("next-root-auth");
        bytes32 nextUriHash = keccak256("next-uri-auth");
        bytes32 nextPolicyHash = keccak256("next-policy-auth");

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashActivateUpgrade(nextRoot, nextUriHash, nextPolicyHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        c.activateUpgradeAuthorized(nextRoot, nextUriHash, nextPolicyHash, deadline, sig);
        assertEq(c.activeRoot(), nextRoot, "active root not updated");
    }

    function test_activateUpgradeAuthorized_accepts_kernelAuthority_root_signature() public {
        uint256 pk1 = 0xA11CE;
        uint256 pk2 = 0xB0B;
        address a1 = vm.addr(pk1);
        address a2 = vm.addr(pk2);

        address[] memory signers = new address[](2);
        if (a1 < a2) {
            signers[0] = a1;
            signers[1] = a2;
        } else {
            signers[0] = a2;
            signers[1] = a1;
        }
        KernelAuthority rootAuth = new KernelAuthority(signers, 2);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(address(rootAuth), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 nextRoot = keccak256("next-root-auth-ka");
        bytes32 nextUriHash = keccak256("next-uri-auth-ka");
        bytes32 nextPolicyHash = keccak256("next-policy-auth-ka");

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashActivateUpgrade(nextRoot, nextUriHash, nextPolicyHash, deadline);

        bytes[] memory sigs = new bytes[](2);
        if (a1 < a2) {
            sigs[0] = _sign(pk1, digest);
            sigs[1] = _sign(pk2, digest);
        } else {
            sigs[0] = _sign(pk2, digest);
            sigs[1] = _sign(pk1, digest);
        }
        bytes memory packed = abi.encode(sigs);

        c.activateUpgradeAuthorized(nextRoot, nextUriHash, nextPolicyHash, deadline, packed);
        assertEq(c.activeRoot(), nextRoot, "active root not updated");
    }

    function test_cancelUpgradeAuthorized_accepts_eoa_root_signature() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 nextRoot = keccak256("next-root-cancel-auth");
        bytes32 nextUriHash = keccak256("next-uri-cancel-auth");
        bytes32 nextPolicyHash = keccak256("next-policy-cancel-auth");

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashCancelUpgrade(nextRoot, nextUriHash, nextPolicyHash, deadline);
        bytes memory sig = _sign(rootPk, digest);

        c.cancelUpgradeAuthorized(nextRoot, nextUriHash, nextPolicyHash, deadline, sig);
        (bytes32 cleared,,,,) = c.pendingUpgrade();
        assertEq(cleared, bytes32(0), "pending not cleared");
    }

    function test_cancelUpgradeAuthorized_accepts_kernelAuthority_root_signature() public {
        uint256 pk1 = 0xA11CE;
        uint256 pk2 = 0xB0B;
        address a1 = vm.addr(pk1);
        address a2 = vm.addr(pk2);

        address[] memory signers = new address[](2);
        if (a1 < a2) {
            signers[0] = a1;
            signers[1] = a2;
        } else {
            signers[0] = a2;
            signers[1] = a1;
        }
        KernelAuthority rootAuth = new KernelAuthority(signers, 2);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(address(rootAuth), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 nextRoot = keccak256("next-root-cancel-auth-ka");
        bytes32 nextUriHash = keccak256("next-uri-cancel-auth-ka");
        bytes32 nextPolicyHash = keccak256("next-policy-cancel-auth-ka");

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashCancelUpgrade(nextRoot, nextUriHash, nextPolicyHash, deadline);

        bytes[] memory sigs = new bytes[](2);
        if (a1 < a2) {
            sigs[0] = _sign(pk1, digest);
            sigs[1] = _sign(pk2, digest);
        } else {
            sigs[0] = _sign(pk2, digest);
            sigs[1] = _sign(pk1, digest);
        }
        bytes memory packed = abi.encode(sigs);

        c.cancelUpgradeAuthorized(nextRoot, nextUriHash, nextPolicyHash, deadline, packed);
        (bytes32 cleared,,,,) = c.pendingUpgrade();
        assertEq(cleared, bytes32(0), "pending not cleared");
    }

    function test_proposeUpgradeByRelease_uses_registry_values() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("blackcat-core");

        registry.publish(component, 1, genesisRoot, genesisUriHash, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        InstanceController c = InstanceController(
            strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 nextRoot = keccak256("release-root");
        bytes32 nextUriHash = keccak256("release-uri");
        registry.publish(component, 2, nextRoot, nextUriHash, 0);

        vm.prank(upgrader);
        c.proposeUpgradeByRelease(component, 2, keccak256("policy2"), 3600);

        (bytes32 pRoot, bytes32 pUri, bytes32 pPolicy,,) = c.pendingUpgrade();
        assertEq(pRoot, nextRoot, "pending root mismatch");
        assertEq(pUri, nextUriHash, "pending uriHash mismatch");
        assertEq(pPolicy, keccak256("policy2"), "pending policyHash mismatch");
    }

    function test_cancelUpgradeExpected_rejects_mismatch() public {
        bytes32 nextRoot = keccak256("next-root-cancel");
        bytes32 nextUriHash = keccak256("next-uri-cancel");
        bytes32 nextPolicyHash = keccak256("next-policy-cancel");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        vm.prank(root);
        vm.expectRevert("InstanceController: pending mismatch");
        controller.cancelUpgradeExpected(nextRoot, keccak256("wrong"), nextPolicyHash);
    }

    function test_snapshotV2_includes_incident_and_flags() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(root);
        controller.setAutoPauseOnBadCheckIn(true);

        vm.prank(reporter);
        controller.checkIn(keccak256("wrong-root"), genesisUriHash, genesisPolicyHash);

        (bool autoPause,,,,,, uint64 incidentCount_,,,, uint256 flags_) = controller.snapshotV2();
        bool paused_ = controller.paused();

        assertTrue(paused_, "paused should be true");
        assertTrue(autoPause, "autoPauseOnBadCheckIn should be true");
        assertEq(uint256(incidentCount_), 1, "incidentCount mismatch");
        assertTrue((flags_ & 1) == 0, "emergencyCanUnpause should default to false");
        assertTrue((flags_ & 2) == 0, "releaseRegistryLocked should default to false");
        assertTrue((flags_ & 4) == 0, "minUpgradeDelayLocked should default to false");
        assertTrue((flags_ & 8) == 0, "emergencyCanUnpauseLocked should default to false");
        assertTrue((flags_ & 16) == 0, "autoPauseOnBadCheckInLocked should default to false");
        assertTrue((flags_ & 32) == 0, "compatibilityWindowLocked should default to false");
        assertTrue((flags_ & 64) == 0, "expectedComponentIdLocked should default to false");
    }

    function test_lockReleaseRegistry_prevents_changes() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("blackcat-core");
        registry.publish(component, 1, genesisRoot, genesisUriHash, 0);

        vm.prank(root);
        controller.setReleaseRegistry(address(registry));

        vm.prank(root);
        controller.lockReleaseRegistry();

        vm.prank(root);
        vm.expectRevert("InstanceController: registry locked");
        controller.setReleaseRegistry(address(0));
    }

    function test_lockMinUpgradeDelay_freezes_value() public {
        vm.prank(root);
        controller.setMinUpgradeDelaySec(60);

        vm.prank(root);
        controller.lockMinUpgradeDelay();

        vm.prank(root);
        vm.expectRevert("InstanceController: delay locked");
        controller.setMinUpgradeDelaySec(0);
    }

    function test_lockMinUpgradeDelay_rejects_zero_delay() public {
        vm.prank(root);
        vm.expectRevert("InstanceController: delay=0");
        controller.lockMinUpgradeDelay();
    }

    function test_activate_upgrade_reverts_when_expired() public {
        bytes32 nextRoot = keccak256("next-root-expire");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, genesisUriHash, genesisPolicyHash, 1);

        (,,, uint64 createdAt, uint64 ttlSec) = controller.pendingUpgrade();
        vm.warp(uint256(createdAt) + uint256(ttlSec) + 1);

        vm.prank(root);
        vm.expectRevert("InstanceController: upgrade expired");
        controller.activateUpgrade();
    }

    function test_activate_upgrade_reverts_when_paused() public {
        bytes32 nextRoot = keccak256("next-root-paused");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, genesisUriHash, genesisPolicyHash, 3600);

        vm.prank(emergency);
        controller.pause();

        vm.prank(root);
        vm.expectRevert("InstanceController: paused");
        controller.activateUpgrade();
    }

    function test_activate_upgrade_enforces_timelock() public {
        uint64 delaySec = 3600;
        bytes32 nextRoot = keccak256("next-root-timelock");

        vm.prank(root);
        controller.setMinUpgradeDelaySec(delaySec);

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, genesisUriHash, genesisPolicyHash, delaySec * 2);

        (,,, uint64 createdAt,) = controller.pendingUpgrade();

        vm.prank(root);
        vm.expectRevert("InstanceController: upgrade timelocked");
        controller.activateUpgrade();

        vm.warp(uint256(createdAt) + uint256(delaySec));

        vm.prank(root);
        controller.activateUpgrade();
        assertEq(controller.activeRoot(), nextRoot, "active root not updated");
    }

    function test_compatibility_window_allows_previous_state_until_expiry() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(root);
        controller.setCompatibilityWindowSec(3600);

        bytes32 nextRoot = keccak256("next-root-compat");
        bytes32 nextUriHash = keccak256("next-uri-compat");
        bytes32 nextPolicyHash = keccak256("next-policy-compat");

        vm.prank(upgrader);
        controller.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        vm.prank(root);
        controller.activateUpgrade();

        (bytes32 cRoot, bytes32 cUri, bytes32 cPolicy, uint64 until) = controller.compatibilityState();
        assertEq(cRoot, genesisRoot, "compat root mismatch");
        assertEq(cUri, genesisUriHash, "compat uri mismatch");
        assertEq(cPolicy, genesisPolicyHash, "compat policy mismatch");
        assertEq(uint256(until), block.timestamp + 3600, "compat until mismatch");

        assertTrue(controller.isAcceptedState(nextRoot, nextUriHash, nextPolicyHash), "active should be accepted");
        assertTrue(
            controller.isAcceptedState(genesisRoot, genesisUriHash, genesisPolicyHash), "compat should be accepted"
        );

        vm.prank(reporter);
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);
        assertTrue(controller.lastCheckInOk(), "compat checkIn should be ok");

        vm.warp(uint256(until) + 1);
        assertTrue(
            !controller.isAcceptedState(genesisRoot, genesisUriHash, genesisPolicyHash), "compat should be expired"
        );
    }

    function test_compatibilityWindow_lock_freezes_value() public {
        vm.prank(root);
        controller.setCompatibilityWindowSec(3600);

        vm.prank(root);
        controller.lockCompatibilityWindow();

        vm.prank(root);
        vm.expectRevert("InstanceController: window locked");
        controller.setCompatibilityWindowSec(0);
    }

    function test_setMinUpgradeDelaySec_rejects_too_large() public {
        uint64 tooLarge = controller.MAX_UPGRADE_DELAY_SEC() + 1;

        vm.prank(root);
        vm.expectRevert("InstanceController: delay too large");
        controller.setMinUpgradeDelaySec(tooLarge);
    }

    function test_proposeUpgrade_rejects_ttl_too_large() public {
        uint64 tooLarge = controller.MAX_UPGRADE_TTL_SEC() + 1;

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: ttl too large");
        controller.proposeUpgrade(keccak256("root"), 0, 0, tooLarge);
    }

    function test_checkIn_tracks_runtime_state() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(reporter);
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);
        assertTrue(controller.lastCheckInOk(), "checkIn should be ok");

        vm.prank(reporter);
        controller.checkIn(keccak256("wrong-root"), genesisUriHash, genesisPolicyHash);
        assertTrue(!controller.lastCheckInOk(), "checkIn should be not ok");
    }

    function test_checkIn_only_reporter() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not reporter authority");
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_checkInAuthorized_accepts_eoa_reporter_signature_and_increments_nonce() public {
        uint256 reporterPk = 0xA11CE;
        address reporter = vm.addr(reporterPk);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = controller.hashCheckIn(genesisRoot, genesisUriHash, genesisPolicyHash, deadline);
        bytes memory sig = _sign(reporterPk, digest);

        uint256 nonceBefore = controller.reporterNonce();
        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, deadline, sig);

        assertEq(controller.reporterNonce(), nonceBefore + 1, "reporterNonce not incremented");
        assertTrue(controller.lastCheckInOk(), "authorized checkIn should be ok");

        vm.expectRevert("InstanceController: invalid reporter signature");
        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, deadline, sig);
    }

    function test_checkInAuthorized_accepts_kernelAuthority_reporter_signature() public {
        uint256 pk1 = 0xA11CE;
        uint256 pk2 = 0xB0B;
        address a1 = vm.addr(pk1);
        address a2 = vm.addr(pk2);

        address[] memory signers = new address[](2);
        if (a1 < a2) {
            signers[0] = a1;
            signers[1] = a2;
        } else {
            signers[0] = a2;
            signers[1] = a1;
        }
        KernelAuthority reporterAuth = new KernelAuthority(signers, 2);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(address(reporterAuth));

        vm.prank(address(reporterAuth));
        controller.acceptReporterAuthority();

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = controller.hashCheckIn(genesisRoot, genesisUriHash, genesisPolicyHash, deadline);

        bytes[] memory sigs = new bytes[](2);
        if (a1 < a2) {
            sigs[0] = _sign(pk1, digest);
            sigs[1] = _sign(pk2, digest);
        } else {
            sigs[0] = _sign(pk2, digest);
            sigs[1] = _sign(pk1, digest);
        }
        bytes memory packed = abi.encode(sigs);

        controller.checkInAuthorized(genesisRoot, genesisUriHash, genesisPolicyHash, deadline, packed);
        assertTrue(controller.lastCheckInOk(), "authorized checkIn should be ok");
    }

    function test_autoPauseOnBadCheckIn_pauses_and_records_incident() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        vm.prank(root);
        controller.setAutoPauseOnBadCheckIn(true);

        vm.prank(reporter);
        controller.checkIn(keccak256("wrong-root"), genesisUriHash, genesisPolicyHash);

        assertTrue(controller.paused(), "controller should auto-pause");
        assertEq(uint256(controller.incidentCount()), 1, "incidentCount mismatch");
        assertEq(controller.lastIncidentBy(), reporter, "lastIncidentBy mismatch");
    }

    function test_autoPauseOnBadCheckIn_lock_freezes_value() public {
        vm.prank(root);
        controller.setAutoPauseOnBadCheckIn(true);

        vm.prank(root);
        controller.lockAutoPauseOnBadCheckIn();

        vm.prank(root);
        vm.expectRevert("InstanceController: auto-pause locked");
        controller.setAutoPauseOnBadCheckIn(false);
    }

    function test_reportIncident_pauses() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);

        vm.prank(reporter);
        controller.acceptReporterAuthority();

        bytes32 incidentHash = keccak256("incident-1");

        vm.prank(reporter);
        controller.reportIncident(incidentHash);

        assertTrue(controller.paused(), "controller should pause on incident");
        assertEq(controller.lastIncidentHash(), incidentHash, "incident hash mismatch");
        assertEq(controller.lastIncidentBy(), reporter, "incident by mismatch");
    }

    function test_reportIncidentAuthorized_accepts_root_signature_and_is_not_replayable() public {
        uint256 rootPk = 0xA11CE;
        address rootAddr = vm.addr(rootPk);

        InstanceFactory f = new InstanceFactory(address(0));
        InstanceController c = InstanceController(
            f.createInstance(rootAddr, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        bytes32 incidentHash = keccak256("incident-auth");
        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = c.hashReportIncident(incidentHash, deadline);
        bytes memory sig = _sign(rootPk, digest);

        uint256 nonceBefore = c.incidentNonce();
        c.reportIncidentAuthorized(incidentHash, deadline, sig);

        assertTrue(c.paused(), "controller should pause on authorized incident");
        assertEq(c.incidentNonce(), nonceBefore + 1, "incidentNonce not incremented");

        vm.expectRevert("InstanceController: invalid incident signature");
        c.reportIncidentAuthorized(incidentHash, deadline, sig);
    }

    function _sign(uint256 pk, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_release_registry_enforces_genesis_and_upgrade_trust() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("blackcat-core");

        registry.publish(component, 1, genesisRoot, 0, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        address instance =
            strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
        InstanceController strictController = InstanceController(instance);

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: root not trusted");
        strictController.proposeUpgrade(keccak256("untrusted-root"), 0, 0, 3600);

        bytes32 nextRoot = keccak256("trusted-root");
        registry.publish(component, 2, nextRoot, 0, 0);

        vm.prank(upgrader);
        strictController.proposeUpgrade(nextRoot, 0, 0, 3600);

        registry.revoke(component, 2);

        vm.prank(root);
        vm.expectRevert("InstanceController: root not trusted");
        strictController.activateUpgrade();
    }

    function test_setExpectedComponentId_rejects_without_registry() public {
        vm.prank(root);
        vm.expectRevert("InstanceController: no registry");
        controller.setExpectedComponentId(keccak256("blackcat-core"));
    }

    function test_expectedComponentId_enforces_component_line_when_registry_is_set() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 componentA = keccak256("blackcat-core");
        bytes32 componentB = keccak256("blackcat-other");

        registry.publish(componentA, 1, genesisRoot, genesisUriHash, 0);

        bytes32 otherRoot = keccak256("other-root");
        registry.publish(componentB, 1, otherRoot, 0, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        InstanceController c = InstanceController(
            strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(root);
        c.setExpectedComponentId(componentA);

        vm.prank(root);
        vm.expectRevert("InstanceController: expected component set");
        c.setReleaseRegistry(address(0));

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: component mismatch");
        c.proposeUpgrade(otherRoot, 0, 0, 3600);

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: component mismatch");
        c.proposeUpgradeByRelease(componentB, 1, 0, 3600);

        bytes32 nextRoot = keccak256("trusted-root-a2");
        registry.publish(componentA, 2, nextRoot, 0, 0);

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, 0, 0, 3600);
    }

    function test_expectedComponentId_lock_prevents_changes() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 componentA = keccak256("blackcat-core");

        registry.publish(componentA, 1, genesisRoot, genesisUriHash, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        InstanceController c = InstanceController(
            strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(root);
        c.setExpectedComponentId(componentA);

        vm.prank(root);
        c.lockExpectedComponentId();

        vm.prank(root);
        vm.expectRevert("InstanceController: expected component locked");
        c.setExpectedComponentId(bytes32(0));
    }

    function test_compatibility_state_rejects_revoked_root_when_registry_is_set() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("blackcat-core");

        registry.publish(component, 1, genesisRoot, genesisUriHash, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        InstanceController c = InstanceController(
            strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        vm.prank(root);
        c.setCompatibilityWindowSec(3600);

        bytes32 nextRoot = keccak256("trusted-root-v2");
        bytes32 nextUriHash = keccak256("trusted-uri-v2");
        bytes32 nextPolicyHash = keccak256("trusted-policy-v2");
        registry.publish(component, 2, nextRoot, nextUriHash, 0);

        vm.prank(upgrader);
        c.proposeUpgrade(nextRoot, nextUriHash, nextPolicyHash, 3600);

        vm.prank(root);
        c.activateUpgrade();

        assertTrue(c.isAcceptedState(genesisRoot, genesisUriHash, genesisPolicyHash), "compat should be accepted");

        registry.revoke(component, 1);

        assertTrue(
            !c.isAcceptedState(genesisRoot, genesisUriHash, genesisPolicyHash), "compat should reject revoked root"
        );
    }

    function test_initialize_rejects_untrusted_genesis_root_when_registry_is_set() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        InstanceFactory strictFactory = new InstanceFactory(address(registry));

        vm.expectRevert("InstanceController: genesis root not trusted");
        strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }
}
