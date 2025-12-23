pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {InstanceController} from "../src/InstanceController.sol";
import {InstanceFactory} from "../src/InstanceFactory.sol";

contract InstanceFactoryTest is TestBase {
    InstanceFactory private factory;

    address private root = address(0x1111111111111111111111111111111111111111);
    address private upgrader = address(0x2222222222222222222222222222222222222222);
    address private emergency = address(0x3333333333333333333333333333333333333333);

    bytes32 private genesisRoot = keccak256("genesis-root");
    bytes32 private genesisUriHash = keccak256("uri");
    bytes32 private genesisPolicyHash = keccak256("policy");

    function setUp() public {
        factory = new InstanceFactory();
    }

    function test_implementation_is_locked() public {
        InstanceController impl = InstanceController(factory.implementation());
        vm.expectRevert("InstanceController: already initialized");
        impl.initialize(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }

    function test_createInstance_initializes_clone() public {
        address instance =
            factory.createInstance(root, upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
        assertTrue(instance != address(0), "instance is zero");
        assertTrue(instance != factory.implementation(), "instance must not equal implementation");

        InstanceController c = InstanceController(instance);
        assertEq(c.rootAuthority(), root, "rootAuthority mismatch");
        assertEq(c.upgradeAuthority(), upgrader, "upgradeAuthority mismatch");
        assertEq(c.emergencyAuthority(), emergency, "emergencyAuthority mismatch");
        assertEq(c.activeRoot(), genesisRoot, "activeRoot mismatch");

        // EIP-1167 runtime code is 45 bytes.
        assertEq(instance.code.length, 45, "unexpected clone code length");
    }

    function test_createInstance_reverts_on_invalid_args() public {
        vm.expectRevert("InstanceController: root=0");
        factory.createInstance(address(0), upgrader, emergency, genesisRoot, genesisUriHash, genesisPolicyHash);
    }
}

