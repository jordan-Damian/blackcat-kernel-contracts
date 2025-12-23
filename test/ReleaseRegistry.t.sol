pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";

contract ReleaseRegistryTest is TestBase {
    address private owner = address(0x1111111111111111111111111111111111111111);
    address private other = address(0x2222222222222222222222222222222222222222);

    function test_constructor_sets_owner() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);
        assertEq(registry.owner(), owner, "owner mismatch");
    }

    function test_constructor_rejects_zero_owner() public {
        vm.expectRevert("ReleaseRegistry: owner=0");
        new ReleaseRegistry(address(0));
    }

    function test_publish_only_owner() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root");
        bytes32 uriHash = keccak256("uri");
        bytes32 metaHash = keccak256("meta");

        vm.prank(other);
        vm.expectRevert("ReleaseRegistry: not owner");
        registry.publish(component, version, root, uriHash, metaHash);

        vm.prank(owner);
        registry.publish(component, version, root, uriHash, metaHash);

        ReleaseRegistry.Release memory rel = registry.get(component, version);
        assertEq(rel.root, root, "root mismatch");
        assertEq(rel.uriHash, uriHash, "uriHash mismatch");
        assertEq(rel.metaHash, metaHash, "metaHash mismatch");
    }

    function test_transferOwnership_only_owner() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        vm.prank(other);
        vm.expectRevert("ReleaseRegistry: not owner");
        registry.transferOwnership(other);

        vm.prank(owner);
        registry.transferOwnership(other);
        assertEq(registry.owner(), other, "owner not transferred");
    }

    function test_publish_rejects_invalid_values() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: componentId=0");
        registry.publish(bytes32(0), 1, keccak256("root"), 0, 0);

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: version=0");
        registry.publish(keccak256("c"), 0, keccak256("root"), 0, 0);

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: root=0");
        registry.publish(keccak256("c"), 1, bytes32(0), 0, 0);
    }
}
