pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";

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
        controller.unpause();
        assertTrue(controller.paused() == false, "unpause failed");

        vm.prank(root);
        vm.expectRevert("InstanceController: not emergency authority");
        controller.pause();
    }

    function test_authority_rotation_only_root() public {
        address newRoot = address(0x4444444444444444444444444444444444444444);

        vm.prank(root);
        controller.setRootAuthority(newRoot);
        assertEq(controller.rootAuthority(), newRoot, "root authority not updated");

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not root authority");
        controller.setUpgradeAuthority(address(0x5555555555555555555555555555555555555555));
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

    function test_setMinUpgradeDelaySec_rejects_too_large() public {
        uint64 tooLarge = controller.MAX_UPGRADE_DELAY_SEC() + 1;

        vm.prank(root);
        vm.expectRevert("InstanceController: delay too large");
        controller.setMinUpgradeDelaySec(tooLarge);
    }

    function test_checkIn_tracks_runtime_state() public {
        address reporter = address(0x7777777777777777777777777777777777777777);

        vm.prank(root);
        controller.setReporterAuthority(reporter);

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
        controller.setReporterAuthority(reporter);

        vm.prank(upgrader);
        vm.expectRevert("InstanceController: not reporter authority");
        controller.checkIn(genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_release_registry_enforces_genesis_and_upgrade_trust() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        bytes32 component = keccak256("blackcat-core");

        registry.publish(component, 1, genesisRoot, 0, 0);

        InstanceFactory strictFactory = new InstanceFactory(address(registry));
        address instance = strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
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

    function test_initialize_rejects_untrusted_genesis_root_when_registry_is_set() public {
        ReleaseRegistry registry = new ReleaseRegistry(address(this));
        InstanceFactory strictFactory = new InstanceFactory(address(registry));

        vm.expectRevert("InstanceController: genesis root not trusted");
        strictFactory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }
}
