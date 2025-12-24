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

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: not pending owner");
        registry.acceptOwnership();

        vm.prank(other);
        registry.acceptOwnership();
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

    function test_publish_is_immutable_per_component_version() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root");

        vm.prank(owner);
        registry.publish(component, version, root, 0, 0);

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: already published");
        registry.publish(component, version, keccak256("root2"), 0, 0);
    }

    function test_publish_rejects_root_reuse_across_releases() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32 componentA = keccak256("blackcat-core");
        bytes32 componentB = keccak256("blackcat-crypto");
        bytes32 root = keccak256("root");

        vm.prank(owner);
        registry.publish(componentA, 1, root, keccak256("uri"), keccak256("meta"));

        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: root already published");
        registry.publish(componentB, 1, root, keccak256("uri2"), keccak256("meta2"));
    }

    function test_publishBatch_publishes_multiple_releases() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32[] memory components = new bytes32[](2);
        uint64[] memory versions = new uint64[](2);
        bytes32[] memory roots = new bytes32[](2);
        bytes32[] memory uriHashes = new bytes32[](2);
        bytes32[] memory metaHashes = new bytes32[](2);

        components[0] = keccak256("blackcat-core");
        components[1] = keccak256("blackcat-crypto");
        versions[0] = 1;
        versions[1] = 1;
        roots[0] = keccak256("root-1");
        roots[1] = keccak256("root-2");
        uriHashes[0] = keccak256("uri-1");
        uriHashes[1] = keccak256("uri-2");
        metaHashes[0] = keccak256("meta-1");
        metaHashes[1] = keccak256("meta-2");

        vm.prank(owner);
        registry.publishBatch(components, versions, roots, uriHashes, metaHashes);

        ReleaseRegistry.Release memory rel1 = registry.get(components[0], versions[0]);
        assertEq(rel1.root, roots[0], "rel1 root mismatch");

        (bytes32 c, uint64 v, bytes32 u, bytes32 m, bool revoked) = registry.getByRoot(roots[1]);
        assertEq(c, components[1], "component mismatch");
        assertEq(uint256(v), uint256(versions[1]), "version mismatch");
        assertEq(u, uriHashes[1], "uriHash mismatch");
        assertEq(m, metaHashes[1], "metaHash mismatch");
        assertTrue(!revoked, "revoked should be false");
    }

    function test_revoke_marks_root_untrusted() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root");

        vm.prank(owner);
        registry.publish(component, version, root, 0, 0);
        assertTrue(registry.isTrustedRoot(root), "root should be trusted after publish");

        vm.prank(owner);
        registry.revoke(component, version);

        assertTrue(registry.isPublishedRoot(root), "root should remain published");
        assertTrue(registry.isRevokedRoot(root), "root should be revoked");
        assertTrue(registry.isRevokedRelease(component, version), "release should be revoked");
        assertTrue(!registry.isTrustedRoot(root), "root should not be trusted after revoke");

        bytes32 otherComponent = keccak256("blackcat-crypto");
        vm.prank(owner);
        vm.expectRevert("ReleaseRegistry: root revoked");
        registry.publish(otherComponent, 1, root, 0, 0);
    }

    function test_revokeByRoot_revokes_release() public {
        ReleaseRegistry registry = new ReleaseRegistry(owner);

        bytes32 component = keccak256("blackcat-core");
        bytes32 root = keccak256("root");

        vm.prank(owner);
        registry.publish(component, 1, root, 0, 0);
        assertTrue(registry.isTrustedRoot(root), "root should be trusted");

        vm.prank(owner);
        registry.revokeByRoot(root);

        assertTrue(registry.isRevokedRoot(root), "root should be revoked");
        assertTrue(!registry.isTrustedRoot(root), "root should not be trusted");
    }

    function test_publishAuthorized_accepts_eoa_owner_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root-auth");
        bytes32 uriHash = keccak256("uri-auth");
        bytes32 metaHash = keccak256("meta-auth");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashPublish(component, version, root, uriHash, metaHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.publishAuthorized(component, version, root, uriHash, metaHash, deadline, sig);
        assertTrue(registry.isTrustedRoot(root), "root should be trusted after publish");
    }

    function test_publishAuthorized_accepts_compact_eip2098_owner_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root-auth-2098");
        bytes32 uriHash = keccak256("uri-auth-2098");
        bytes32 metaHash = keccak256("meta-auth-2098");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashPublish(component, version, root, uriHash, metaHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = toEip2098Signature(v, r, s);

        registry.publishAuthorized(component, version, root, uriHash, metaHash, deadline, sig);
        assertTrue(registry.isTrustedRoot(root), "root should be trusted after publish");
    }

    function test_publishAuthorized_rejects_high_s_malleable_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root-auth-high-s");
        bytes32 uriHash = keccak256("uri-auth-high-s");
        bytes32 metaHash = keccak256("meta-auth-high-s");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashPublish(component, version, root, uriHash, metaHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        uint256 altS = SECP256K1N - uint256(s);
        assertTrue(altS > SECP256K1N_HALF, "signature is not high-s");
        bytes memory malleable = toMalleableHighSSignature(v, r, s);

        vm.expectRevert("ReleaseRegistry: bad s");
        registry.publishAuthorized(component, version, root, uriHash, metaHash, deadline, malleable);
    }

    function test_publishAuthorized_is_not_replayable() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root-auth-replay");
        bytes32 uriHash = keccak256("uri-auth-replay");
        bytes32 metaHash = keccak256("meta-auth-replay");

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashPublish(component, version, root, uriHash, metaHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.publishAuthorized(component, version, root, uriHash, metaHash, deadline, sig);

        vm.expectRevert("ReleaseRegistry: invalid owner signature");
        registry.publishAuthorized(component, version, root, uriHash, metaHash, deadline, sig);
    }

    function test_publishBatchAuthorized_accepts_eoa_owner_signature_and_is_not_replayable() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        ReleaseRegistry.PublishBatchItem[] memory items = new ReleaseRegistry.PublishBatchItem[](2);
        items[0] = ReleaseRegistry.PublishBatchItem({
            componentId: keccak256("blackcat-core"),
            version: 1,
            root: keccak256("root-batch-1"),
            uriHash: keccak256("uri-batch-1"),
            metaHash: keccak256("meta-batch-1")
        });
        items[1] = ReleaseRegistry.PublishBatchItem({
            componentId: keccak256("blackcat-crypto"),
            version: 1,
            root: keccak256("root-batch-2"),
            uriHash: keccak256("uri-batch-2"),
            metaHash: keccak256("meta-batch-2")
        });

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashPublishBatch(items, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.publishBatchAuthorized(items, deadline, sig);
        assertTrue(registry.isTrustedRoot(items[0].root), "root1 should be trusted");
        assertTrue(registry.isTrustedRoot(items[1].root), "root2 should be trusted");

        vm.expectRevert("ReleaseRegistry: invalid owner signature");
        registry.publishBatchAuthorized(items, deadline, sig);
    }

    function test_publishBatchAuthorized_rejects_empty_batch() public {
        address ownerAddr = vm.addr(0xA11CE);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        ReleaseRegistry.PublishBatchItem[] memory items = new ReleaseRegistry.PublishBatchItem[](0);

        uint256 deadline = block.timestamp + 3600;
        vm.expectRevert("ReleaseRegistry: empty batch");
        registry.publishBatchAuthorized(items, deadline, "");
    }

    function test_revokeAuthorized_accepts_eoa_owner_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        uint64 version = 1;
        bytes32 root = keccak256("root-revoke-auth");

        vm.prank(ownerAddr);
        registry.publish(component, version, root, 0, 0);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevoke(component, version, root, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.revokeAuthorized(component, version, root, deadline, sig);
        assertTrue(registry.isRevokedRoot(root), "root should be revoked");
    }

    function test_revokeBatchAuthorized_accepts_eoa_owner_signature_and_is_not_replayable() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 componentA = keccak256("blackcat-core");
        bytes32 componentB = keccak256("blackcat-crypto");
        bytes32 rootA = keccak256("root-revoke-batch-1");
        bytes32 rootB = keccak256("root-revoke-batch-2");

        vm.prank(ownerAddr);
        registry.publish(componentA, 1, rootA, 0, 0);
        vm.prank(ownerAddr);
        registry.publish(componentB, 1, rootB, 0, 0);

        ReleaseRegistry.RevokeBatchItem[] memory items = new ReleaseRegistry.RevokeBatchItem[](2);
        items[0] = ReleaseRegistry.RevokeBatchItem({componentId: componentA, version: 1, root: rootA});
        items[1] = ReleaseRegistry.RevokeBatchItem({componentId: componentB, version: 1, root: rootB});

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevokeBatch(items, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.revokeBatchAuthorized(items, deadline, sig);
        assertTrue(registry.isRevokedRoot(rootA), "rootA should be revoked");
        assertTrue(registry.isRevokedRoot(rootB), "rootB should be revoked");

        vm.expectRevert("ReleaseRegistry: invalid owner signature");
        registry.revokeBatchAuthorized(items, deadline, sig);
    }

    function test_revokeByRootAuthorized_accepts_eoa_owner_signature() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        bytes32 component = keccak256("blackcat-core");
        bytes32 root = keccak256("root-revoke-by-root");

        vm.prank(ownerAddr);
        registry.publish(component, 1, root, 0, 0);

        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = registry.hashRevokeByRoot(root, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        registry.revokeByRootAuthorized(root, deadline, sig);
        assertTrue(registry.isRevokedRoot(root), "root should be revoked");
    }

    function test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        uint256 newOwnerPk = 0xB0B;
        address newOwnerAddr = vm.addr(newOwnerPk);

        ReleaseRegistry registry = new ReleaseRegistry(ownerAddr);

        uint256 deadline1 = block.timestamp + 3600;
        bytes32 digest1 = registry.hashTransferOwnership(newOwnerAddr, deadline1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPk, digest1);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);
        registry.transferOwnershipAuthorized(newOwnerAddr, deadline1, sig1);

        uint256 deadline2 = block.timestamp + 7200;
        bytes32 digest2 = registry.hashAcceptOwnership(newOwnerAddr, deadline2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(newOwnerPk, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        registry.acceptOwnershipAuthorized(newOwnerAddr, deadline2, sig2);

        assertEq(registry.owner(), newOwnerAddr, "owner not transferred");
    }

    function testFuzz_publish_then_getByRoot_roundtrip(
        bytes32 componentId,
        uint64 version,
        bytes32 root,
        bytes32 uriHash,
        bytes32 metaHash
    ) public {
        vm.assume(componentId != bytes32(0));
        vm.assume(version != 0);
        vm.assume(root != bytes32(0));

        ReleaseRegistry registry = new ReleaseRegistry(owner);
        vm.prank(owner);
        registry.publish(componentId, version, root, uriHash, metaHash);

        (bytes32 c, uint64 v, bytes32 u, bytes32 m, bool revoked) = registry.getByRoot(root);
        assertEq(c, componentId, "component mismatch");
        assertEq(uint256(v), uint256(version), "version mismatch");
        assertEq(u, uriHash, "uriHash mismatch");
        assertEq(m, metaHash, "metaHash mismatch");
        assertTrue(!revoked, "revoked should be false");
    }
}
