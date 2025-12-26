/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";

contract AlwaysTrustedRegistry {
    function isTrustedRoot(bytes32) external pure returns (bool) {
        return true;
    }
}

/// @notice Lightweight “stateful fuzz” tests without external dependencies.
/// @dev We intentionally ignore reverts for random operations and assert invariants after each step.
contract InstanceControllerStatefulFuzzTest is TestBase {
    InstanceFactory private factory;
    InstanceController private controller;
    AlwaysTrustedRegistry private registry;

    uint256 private rootPk;
    uint256 private upgraderPk;
    uint256 private emergencyPk;
    uint256 private reporterPk;

    address private root;
    address private upgrader;
    address private emergency;
    address private reporter;

    bytes32 private genesisRoot;
    bytes32 private genesisUriHash;
    bytes32 private genesisPolicyHash;

    bool private minDelayLockedSeen;
    uint64 private minDelayLockedValue;

    bool private maxCheckInAgeLockedSeen;
    uint64 private maxCheckInAgeLockedValue;

    bool private autoPauseLockedSeen;
    bool private autoPauseLockedValue;

    bool private emergencyUnpauseLockedSeen;
    bool private emergencyUnpauseLockedValue;

    bool private compatWindowLockedSeen;
    uint64 private compatWindowLockedValue;

    bool private releaseRegistryLockedSeen;
    address private releaseRegistryLockedValue;

    function setUp() public {
        minDelayLockedSeen = false;
        minDelayLockedValue = 0;
        maxCheckInAgeLockedSeen = false;
        maxCheckInAgeLockedValue = 0;
        autoPauseLockedSeen = false;
        autoPauseLockedValue = false;
        emergencyUnpauseLockedSeen = false;
        emergencyUnpauseLockedValue = false;
        compatWindowLockedSeen = false;
        compatWindowLockedValue = 0;
        releaseRegistryLockedSeen = false;
        releaseRegistryLockedValue = address(0);

        rootPk = 0xA11CE;
        upgraderPk = 0xB0B;
        emergencyPk = 0xCAFE;
        reporterPk = 0xD00D;

        root = vm.addr(rootPk);
        upgrader = vm.addr(upgraderPk);
        emergency = vm.addr(emergencyPk);
        reporter = vm.addr(reporterPk);

        genesisRoot = keccak256("genesis-root");
        genesisUriHash = keccak256("genesis-uri");
        genesisPolicyHash = keccak256("genesis-policy");

        factory = new InstanceFactory(address(0));
        controller = InstanceController(
            factory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash)
        );

        registry = new AlwaysTrustedRegistry();

        vm.prank(root);
        controller.startReporterAuthorityTransfer(reporter);
        vm.prank(reporter);
        controller.acceptReporterAuthority();
    }

    function testFuzz_stateful_knob_lock_invariants(uint256 seed) public {
        uint256 steps = (seed % 16) + 1;

        for (uint256 i = 0; i < steps; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            _step(seed);
            _recordLocks();
            _assertLockInvariants();
            _assertAlwaysNonZeroAuthorities();
            _assertExpectedComponentImpliesRegistry();
        }
    }

    function _step(uint256 seed) private {
        uint8 op = uint8(seed % 18);
        uint64 small = uint64(seed % 3000);
        bool flag = (seed & 1) == 1;

        if (op == 0) {
            _tryAsRoot(abi.encodeCall(InstanceController.setMinUpgradeDelaySec, (small % 300)));
            return;
        }
        if (op == 1) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockMinUpgradeDelay, ()));
            return;
        }
        if (op == 2) {
            _tryAsRoot(abi.encodeCall(InstanceController.setMaxCheckInAgeSec, (uint64((small % 300) + 1))));
            return;
        }
        if (op == 3) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockMaxCheckInAgeSec, ()));
            return;
        }
        if (op == 4) {
            _tryAsRoot(abi.encodeCall(InstanceController.setAutoPauseOnBadCheckIn, (flag)));
            return;
        }
        if (op == 5) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockAutoPauseOnBadCheckIn, ()));
            return;
        }
        if (op == 6) {
            _tryAsRoot(abi.encodeCall(InstanceController.setCompatibilityWindowSec, (small % 3600)));
            return;
        }
        if (op == 7) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockCompatibilityWindow, ()));
            return;
        }
        if (op == 8) {
            _tryAsRoot(abi.encodeCall(InstanceController.setEmergencyCanUnpause, (flag)));
            return;
        }
        if (op == 9) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockEmergencyCanUnpause, ()));
            return;
        }
        if (op == 10) {
            _tryWithSender(flag ? emergency : root, abi.encodeCall(InstanceController.pause, ()));
            return;
        }
        if (op == 11) {
            _tryWithSender(flag ? emergency : root, abi.encodeCall(InstanceController.unpause, ()));
            return;
        }
        if (op == 12) {
            bytes32 nextRoot = keccak256(abi.encodePacked("upgrade-root", seed));
            bytes32 nextUriHash = keccak256(abi.encodePacked("upgrade-uri", seed));
            bytes32 nextPolicyHash = keccak256(abi.encodePacked("upgrade-policy", seed));
            _tryAsUpgrader(
                abi.encodeCall(InstanceController.proposeUpgrade, (nextRoot, nextUriHash, nextPolicyHash, 3600))
            );
            return;
        }
        if (op == 13) {
            _tryAsRoot(abi.encodeCall(InstanceController.activateUpgrade, ()));
            return;
        }
        if (op == 14) {
            _tryWithSender(flag ? upgrader : root, abi.encodeCall(InstanceController.cancelUpgrade, ()));
            return;
        }
        if (op == 15) {
            _tryAsRoot(abi.encodeCall(InstanceController.setReleaseRegistry, (address(registry))));
            return;
        }
        if (op == 16) {
            _tryAsRoot(abi.encodeCall(InstanceController.lockReleaseRegistry, ()));
            return;
        }

        _tryAsRoot(abi.encodeCall(InstanceController.setReleaseRegistry, (address(0))));
    }

    function _tryAsRoot(bytes memory data) private {
        _tryWithSender(root, data);
    }

    function _tryAsUpgrader(bytes memory data) private {
        _tryWithSender(upgrader, data);
    }

    function _tryWithSender(address sender, bytes memory data) private {
        vm.prank(sender);
        (bool ok,) = address(controller).call(data);
        ok;
    }

    function _recordLocks() private {
        if (!minDelayLockedSeen && controller.minUpgradeDelayLocked()) {
            minDelayLockedSeen = true;
            minDelayLockedValue = controller.minUpgradeDelaySec();
        }

        if (!maxCheckInAgeLockedSeen && controller.maxCheckInAgeLocked()) {
            maxCheckInAgeLockedSeen = true;
            maxCheckInAgeLockedValue = controller.maxCheckInAgeSec();
        }

        if (!autoPauseLockedSeen && controller.autoPauseOnBadCheckInLocked()) {
            autoPauseLockedSeen = true;
            autoPauseLockedValue = controller.autoPauseOnBadCheckIn();
        }

        if (!emergencyUnpauseLockedSeen && controller.emergencyCanUnpauseLocked()) {
            emergencyUnpauseLockedSeen = true;
            emergencyUnpauseLockedValue = controller.emergencyCanUnpause();
        }

        if (!compatWindowLockedSeen && controller.compatibilityWindowLocked()) {
            compatWindowLockedSeen = true;
            compatWindowLockedValue = controller.compatibilityWindowSec();
        }

        if (!releaseRegistryLockedSeen && controller.releaseRegistryLocked()) {
            releaseRegistryLockedSeen = true;
            releaseRegistryLockedValue = controller.releaseRegistry();
        }
    }

    function _assertLockInvariants() private view {
        if (minDelayLockedSeen) {
            assertEq(uint256(controller.minUpgradeDelaySec()), uint256(minDelayLockedValue), "minUpgradeDelay mutated");
        }
        if (maxCheckInAgeLockedSeen) {
            assertEq(uint256(controller.maxCheckInAgeSec()), uint256(maxCheckInAgeLockedValue), "maxCheckInAge mutated");
        }
        if (autoPauseLockedSeen) {
            assertTrue(controller.autoPauseOnBadCheckIn() == autoPauseLockedValue, "autoPause mutated");
        }
        if (emergencyUnpauseLockedSeen) {
            assertTrue(controller.emergencyCanUnpause() == emergencyUnpauseLockedValue, "emergencyCanUnpause mutated");
        }
        if (compatWindowLockedSeen) {
            assertEq(
                uint256(controller.compatibilityWindowSec()), uint256(compatWindowLockedValue), "compatWindow mutated"
            );
        }
        if (releaseRegistryLockedSeen) {
            assertEq(controller.releaseRegistry(), releaseRegistryLockedValue, "releaseRegistry mutated");
        }
    }

    function _assertAlwaysNonZeroAuthorities() private view {
        assertTrue(controller.rootAuthority() != address(0), "rootAuthority must not be zero");
        assertTrue(controller.upgradeAuthority() != address(0), "upgradeAuthority must not be zero");
        assertTrue(controller.emergencyAuthority() != address(0), "emergencyAuthority must not be zero");
        assertTrue(controller.activeRoot() != bytes32(0), "activeRoot must not be zero");
    }

    function _assertExpectedComponentImpliesRegistry() private view {
        bytes32 expected = controller.expectedComponentId();
        if (expected != bytes32(0)) {
            assertTrue(controller.releaseRegistry() != address(0), "expectedComponentId set without registry");
        }
    }
}
