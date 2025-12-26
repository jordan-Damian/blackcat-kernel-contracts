/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract StatefulCounter {
    uint256 public n;

    function inc() external {
        n += 1;
    }
}

/// @notice Lightweight “stateful fuzz” tests without external dependencies.
/// @dev We focus on nonce monotonicity and “no side effects on revert”.
contract KernelAuthorityStatefulFuzzTest is TestBase {
    struct Signer {
        address addr;
        uint256 pk;
    }

    function testFuzz_stateful_nonce_and_calls(uint256 seed) public {
        Signer memory s1 = Signer({addr: vm.addr(0xA11CE), pk: 0xA11CE});
        Signer memory s2 = Signer({addr: vm.addr(0xB0B), pk: 0xB0B});

        if (s2.addr < s1.addr) {
            Signer memory tmp = s1;
            s1 = s2;
            s2 = tmp;
        }

        address[] memory signers = new address[](2);
        signers[0] = s1.addr;
        signers[1] = s2.addr;

        KernelAuthority authority = new KernelAuthority(signers, 2);
        StatefulCounter counter = new StatefulCounter();

        uint256 expectedNonce = authority.nonce();
        uint256 expectedCounter = counter.n();

        address[] memory signers0 = authority.getSigners();
        uint256 threshold0 = authority.threshold();
        assertEq(signers0.length, 2, "signers length mismatch");
        assertEq(signers0[0], s1.addr, "signer[0] mismatch");
        assertEq(signers0[1], s2.addr, "signer[1] mismatch");
        assertEq(threshold0, 2, "threshold mismatch");

        uint256 steps = (seed % 16) + 1;

        for (uint256 i = 0; i < steps; i++) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint8 op = uint8(seed % 6);

            if (op == 0) {
                // Valid execute (inc).
                bytes memory data = abi.encodeWithSignature("inc()");
                uint256 deadline = block.timestamp + 3600;
                bytes32 digest = authority.hashExecute(address(counter), 0, data, expectedNonce, deadline);

                bytes[] memory sigs = new bytes[](2);
                sigs[0] = _signDigest(s1, digest);
                sigs[1] = _signDigest(s2, digest);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.execute, (address(counter), 0, data, deadline, sigs)));
                assertTrue(ok, "execute should succeed");

                expectedNonce += 1;
                expectedCounter += 1;
            } else if (op == 1) {
                // Invalid execute (insufficient signatures).
                bytes memory data = abi.encodeWithSignature("inc()");
                uint256 deadline = block.timestamp + 3600;
                bytes32 digest = authority.hashExecute(address(counter), 0, data, expectedNonce, deadline);

                bytes[] memory sigs = new bytes[](1);
                sigs[0] = _signDigest(s1, digest);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.execute, (address(counter), 0, data, deadline, sigs)));
                assertTrue(!ok, "execute must fail with insufficient signatures");
            } else if (op == 2) {
                // Invalid execute (unordered signatures).
                bytes memory data = abi.encodeWithSignature("inc()");
                uint256 deadline = block.timestamp + 3600;
                bytes32 digest = authority.hashExecute(address(counter), 0, data, expectedNonce, deadline);

                bytes[] memory sigs = new bytes[](2);
                sigs[0] = _signDigest(s2, digest);
                sigs[1] = _signDigest(s1, digest);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.execute, (address(counter), 0, data, deadline, sigs)));
                assertTrue(!ok, "execute must fail with unordered signatures");
            } else if (op == 3) {
                // Invalid execute (expired deadline).
                bytes memory data = abi.encodeWithSignature("inc()");
                uint256 deadline = block.timestamp + 1;
                bytes32 digest = authority.hashExecute(address(counter), 0, data, expectedNonce, deadline);

                bytes[] memory sigs = new bytes[](2);
                sigs[0] = _signDigest(s1, digest);
                sigs[1] = _signDigest(s2, digest);

                vm.warp(deadline + 1);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.execute, (address(counter), 0, data, deadline, sigs)));
                assertTrue(!ok, "execute must fail when expired");
            } else if (op == 4) {
                // Valid executeBatch (two increments).
                address[] memory targets = new address[](2);
                uint256[] memory values = new uint256[](2);
                bytes[] memory data = new bytes[](2);
                targets[0] = address(counter);
                targets[1] = address(counter);
                values[0] = 0;
                values[1] = 0;
                data[0] = abi.encodeWithSignature("inc()");
                data[1] = abi.encodeWithSignature("inc()");

                uint256 deadline = block.timestamp + 3600;
                bytes32 digest = authority.hashExecuteBatch(targets, values, data, expectedNonce, deadline);

                bytes[] memory sigs = new bytes[](2);
                sigs[0] = _signDigest(s1, digest);
                sigs[1] = _signDigest(s2, digest);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.executeBatch, (targets, values, data, deadline, sigs)));
                assertTrue(ok, "executeBatch should succeed");

                expectedNonce += 1;
                expectedCounter += 2;
            } else {
                // Invalid executeBatch (length mismatch).
                address[] memory targets = new address[](2);
                uint256[] memory values = new uint256[](1);
                bytes[] memory data = new bytes[](2);
                targets[0] = address(counter);
                targets[1] = address(counter);
                values[0] = 0;
                data[0] = abi.encodeWithSignature("inc()");
                data[1] = abi.encodeWithSignature("inc()");

                uint256 deadline = block.timestamp + 3600;
                bytes[] memory sigs = new bytes[](0);

                (bool ok,) = address(authority)
                    .call(abi.encodeCall(KernelAuthority.executeBatch, (targets, values, data, deadline, sigs)));
                assertTrue(!ok, "executeBatch must fail on length mismatch");
            }

            // Invariants: nonce and observable side effects.
            assertEq(authority.nonce(), expectedNonce, "nonce drift");
            assertEq(counter.n(), expectedCounter, "counter drift");

            // Config must remain stable (we never call setConfig).
            assertEq(authority.threshold(), threshold0, "threshold mutated");
            address[] memory signersNow = authority.getSigners();
            assertEq(signersNow.length, signers0.length, "signers length mutated");
            assertEq(signersNow[0], signers0[0], "signer[0] mutated");
            assertEq(signersNow[1], signers0[1], "signer[1] mutated");
        }
    }

    function _signDigest(Signer memory s, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(s.pk, digest);
        return abi.encodePacked(r, s_, v);
    }
}

