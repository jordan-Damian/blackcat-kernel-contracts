/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract Counter {
    uint256 public n;

    function inc() external {
        n += 1;
    }

    function fail() external pure {
        require(false, "fail");
    }
}

contract KernelAuthorityTest is TestBase {
    Counter private counter;
    KernelAuthority private authority;

    struct Signer {
        address addr;
        uint256 pk;
    }

    Signer private s1;
    Signer private s2;

    function setUp() public {
        counter = new Counter();

        s1.pk = 0xA11CE;
        s2.pk = 0xB0B;
        s1.addr = vm.addr(s1.pk);
        s2.addr = vm.addr(s2.pk);

        (Signer memory a, Signer memory b) = _sortSigners(s1, s2);
        s1 = a;
        s2 = b;

        address[] memory signers = new address[](2);
        signers[0] = s1.addr;
        signers[1] = s2.addr;

        authority = new KernelAuthority(signers, 2);
    }

    function test_constructor_rejects_unsorted_signers() public {
        address[] memory signers = new address[](2);
        signers[0] = address(0x2);
        signers[1] = address(0x1);

        vm.expectRevert("KernelAuthority: signers not ordered");
        new KernelAuthority(signers, 1);
    }

    function test_execute_requires_threshold_signatures() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 3600;

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _signExecute(s1, address(counter), 0, data, authority.nonce(), deadline);

        vm.expectRevert("KernelAuthority: insufficient signatures");
        authority.execute(address(counter), 0, data, deadline, sigs);
    }

    function test_execute_rejects_unsorted_signatures() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 3600;

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signExecute(s2, address(counter), 0, data, authority.nonce(), deadline);
        sigs[1] = _signExecute(s1, address(counter), 0, data, authority.nonce(), deadline);

        vm.expectRevert("KernelAuthority: signers not ordered");
        authority.execute(address(counter), 0, data, deadline, sigs);
    }

    function test_execute_increments_nonce_and_calls_target() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signExecute(s1, address(counter), 0, data, nonceBefore, deadline);
        sigs[1] = _signExecute(s2, address(counter), 0, data, nonceBefore, deadline);

        authority.execute(address(counter), 0, data, deadline, sigs);
        assertEq(counter.n(), 1, "counter did not increment");
        assertEq(authority.nonce(), nonceBefore + 1, "nonce not incremented");
    }

    function test_execute_accepts_compact_eip2098_signatures() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecute(address(counter), 0, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        (uint8 v1, bytes32 r1, bytes32 s1_) = vm.sign(s1.pk, digest);
        (uint8 v2, bytes32 r2, bytes32 s2_) = vm.sign(s2.pk, digest);
        sigs[0] = toEip2098Signature(v1, r1, s1_);
        sigs[1] = toEip2098Signature(v2, r2, s2_);

        authority.execute(address(counter), 0, data, deadline, sigs);
        assertEq(counter.n(), 1, "counter did not increment");
        assertEq(authority.nonce(), nonceBefore + 1, "nonce not incremented");
    }

    function test_execute_rejects_high_s_malleable_signature() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecute(address(counter), 0, data, nonceBefore, deadline);

        (uint8 v1, bytes32 r1, bytes32 s1_) = vm.sign(s1.pk, digest);
        uint256 altS = SECP256K1N - uint256(s1_);
        assertTrue(altS > SECP256K1N_HALF, "signature is not high-s");

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = toMalleableHighSSignature(v1, r1, s1_);
        sigs[1] = _signDigest(s2, digest);

        vm.expectRevert("KernelAuthority: bad s");
        authority.execute(address(counter), 0, data, deadline, sigs);
    }

    function test_executeBatch_runs_multiple_calls() public {
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
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecuteBatch(targets, values, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s1, digest);
        sigs[1] = _signDigest(s2, digest);

        authority.executeBatch(targets, values, data, deadline, sigs);

        assertEq(counter.n(), 2, "counter did not increment twice");
        assertEq(authority.nonce(), nonceBefore + 1, "nonce not incremented");
    }

    function test_executeBatch_bubbles_revert_reason() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(counter);
        targets[1] = address(counter);
        values[0] = 0;
        values[1] = 0;
        data[0] = abi.encodeWithSignature("inc()");
        data[1] = abi.encodeWithSignature("fail()");

        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecuteBatch(targets, values, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s1, digest);
        sigs[1] = _signDigest(s2, digest);

        vm.expectRevert("fail");
        authority.executeBatch(targets, values, data, deadline, sigs);
    }

    function test_execute_rejects_expired_deadline() public {
        bytes memory data = abi.encodeWithSignature("inc()");
        uint256 deadline = block.timestamp + 1;

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signExecute(s1, address(counter), 0, data, authority.nonce(), deadline);
        sigs[1] = _signExecute(s2, address(counter), 0, data, authority.nonce(), deadline);

        vm.warp(deadline + 1);

        vm.expectRevert("KernelAuthority: expired");
        authority.execute(address(counter), 0, data, deadline, sigs);
    }

    function test_execute_bubbles_revert_reason() public {
        bytes memory data = abi.encodeWithSignature("fail()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signExecute(s1, address(counter), 0, data, nonceBefore, deadline);
        sigs[1] = _signExecute(s2, address(counter), 0, data, nonceBefore, deadline);

        vm.expectRevert("fail");
        authority.execute(address(counter), 0, data, deadline, sigs);
    }

    function test_setConfig_only_self_via_execute() public {
        address[] memory newSigners = new address[](1);
        newSigners[0] = s1.addr;

        bytes memory data = abi.encodeCall(KernelAuthority.setConfig, (newSigners, 1));
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signExecute(s1, address(authority), 0, data, nonceBefore, deadline);
        sigs[1] = _signExecute(s2, address(authority), 0, data, nonceBefore, deadline);

        authority.execute(address(authority), 0, data, deadline, sigs);

        assertEq(authority.threshold(), 1, "threshold mismatch");
        assertTrue(authority.isSigner(s1.addr), "signer1 should remain");
        assertTrue(!authority.isSigner(s2.addr), "signer2 should be removed");
    }

    function test_isValidSignature_accepts_packed_bytes_array() public {
        bytes32 digest = keccak256("digest");

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s1, digest);
        sigs[1] = _signDigest(s2, digest);

        bytes memory packed = abi.encode(sigs);
        assertEq(authority.isValidSignature(digest, packed), bytes4(0x1626ba7e), "should be valid");
    }

    function test_isValidSignature_rejects_insufficient_or_unsorted() public {
        bytes32 digest = keccak256("digest");

        bytes[] memory sigs1 = new bytes[](1);
        sigs1[0] = _signDigest(s1, digest);
        bytes memory packed1 = abi.encode(sigs1);
        assertEq(authority.isValidSignature(digest, packed1), bytes4(0), "should be invalid");

        bytes[] memory sigs2 = new bytes[](2);
        sigs2[0] = _signDigest(s2, digest);
        sigs2[1] = _signDigest(s1, digest);
        bytes memory packed2 = abi.encode(sigs2);
        assertEq(authority.isValidSignature(digest, packed2), bytes4(0), "should be invalid");
    }

    function _signExecute(
        Signer memory signer,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce_,
        uint256 deadline
    ) private returns (bytes memory) {
        bytes32 digest = authority.hashExecute(target, value, data, nonce_, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signDigest(Signer memory signer, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sortSigners(Signer memory a, Signer memory b) private pure returns (Signer memory, Signer memory) {
        if (a.addr < b.addr) {
            return (a, b);
        }
        return (b, a);
    }
}
