/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {ReleaseRegistry} from "../src/ReleaseRegistry.sol";

/// @notice Lightweight “stateful fuzz” tests without external dependencies.
/// @dev We intentionally ignore reverts for random operations and assert invariants at the end.
contract ReleaseRegistryStatefulFuzzTest is TestBase {
    function testFuzz_stateful_publish_revoke_invariants(uint256 seed) public {
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);

        ReleaseRegistry registry = new ReleaseRegistry(owner);

        uint256 steps = (seed % 24) + 1;

        bytes32[] memory roots = new bytes32[](steps);
        bytes32[] memory componentIds = new bytes32[](steps);
        uint64[] memory versions = new uint64[](steps);
        bool[] memory revoked = new bool[](steps);
        uint256 publishedCount = 0;

        for (uint256 i = 0; i < steps; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint8 op = uint8(seed % 3);

            if (op == 0) {
                bytes32 componentId = keccak256(abi.encodePacked("comp", seed, i));
                uint64 version = uint64((seed % 8) + 1);
                bytes32 root = keccak256(abi.encodePacked("root", seed, i));
                bytes32 uriHash = keccak256(abi.encodePacked("uri", seed, i));
                bytes32 metaHash = keccak256(abi.encodePacked("meta", seed, i));

                bool publishOk = _tryAs(
                    owner,
                    address(registry),
                    abi.encodeCall(ReleaseRegistry.publish, (componentId, version, root, uriHash, metaHash))
                );
                if (publishOk) {
                    componentIds[publishedCount] = componentId;
                    versions[publishedCount] = version;
                    roots[publishedCount] = root;
                    revoked[publishedCount] = false;
                    publishedCount += 1;
                }

                continue;
            }

            if (publishedCount == 0) {
                continue;
            }

            uint256 idx = seed % publishedCount;

            if (op == 1) {
                bool revokeOk = _tryAs(
                    owner, address(registry), abi.encodeCall(ReleaseRegistry.revoke, (componentIds[idx], versions[idx]))
                );
                if (revokeOk) {
                    revoked[idx] = true;
                }
                continue;
            }

            bool revokeByRootOk =
                _tryAs(owner, address(registry), abi.encodeCall(ReleaseRegistry.revokeByRoot, (roots[idx])));
            if (revokeByRootOk) {
                revoked[idx] = true;
            }
        }

        for (uint256 i = 0; i < publishedCount; i++) {
            ReleaseRegistry.Release memory rel = registry.get(componentIds[i], versions[i]);
            assertEq(rel.root, roots[i], "release root mismatch");

            assertTrue(registry.isPublishedRoot(roots[i]), "root must remain published");
            assertTrue(registry.isTrustedRoot(roots[i]) == !revoked[i], "trustedRoot mismatch");
            assertTrue(registry.isRevokedRoot(roots[i]) == revoked[i], "revokedRoot mismatch");
            assertTrue(registry.isRevokedRelease(componentIds[i], versions[i]) == revoked[i], "revokedRelease mismatch");

            (bytes32 c, uint64 v,,, bool r) = registry.getByRoot(roots[i]);
            assertEq(c, componentIds[i], "getByRoot component mismatch");
            assertEq(uint256(v), uint256(versions[i]), "getByRoot version mismatch");
            assertTrue(r == revoked[i], "getByRoot revoked mismatch");
        }
    }

    function _tryAs(address sender, address target, bytes memory data) private returns (bool ok) {
        vm.prank(sender);
        (ok,) = target.call(data);
    }
}
