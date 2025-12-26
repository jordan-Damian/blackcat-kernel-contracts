/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {KernelAuthority} from "../src/KernelAuthority.sol";

contract ValueReceiver {
    uint256 public receivedCount;
    uint256 public lastValue;

    receive() external payable {
        receivedCount += 1;
        lastValue = msg.value;
    }
}

contract KernelAuthorityAdditionalTest is TestBase {
    struct Signer {
        address addr;
        uint256 pk;
    }

    Signer private s0;
    Signer private s1;
    Signer private s2;

    KernelAuthority private authority;
    ValueReceiver private receiver;

    function setUp() public {
        receiver = new ValueReceiver();

        Signer memory a = Signer({pk: 0xA11CE, addr: vm.addr(0xA11CE)});
        Signer memory b = Signer({pk: 0xB0B, addr: vm.addr(0xB0B)});
        Signer memory c = Signer({pk: 0xC0DE, addr: vm.addr(0xC0DE)});

        Signer[3] memory sorted = _sort3(a, b, c);
        s0 = sorted[0];
        s1 = sorted[1];
        s2 = sorted[2];

        address[] memory signers = new address[](3);
        signers[0] = s0.addr;
        signers[1] = s1.addr;
        signers[2] = s2.addr;

        authority = new KernelAuthority(signers, 2);
    }

    function test_constructor_rejects_threshold_zero() public {
        address[] memory signers = new address[](1);
        signers[0] = address(0x1234);

        vm.expectRevert("KernelAuthority: bad threshold");
        new KernelAuthority(signers, 0);
    }

    function test_constructor_rejects_threshold_above_signers_length() public {
        address[] memory signers = new address[](1);
        signers[0] = address(0x1234);

        vm.expectRevert("KernelAuthority: bad threshold");
        new KernelAuthority(signers, 2);
    }

    function test_constructor_rejects_signer_zero() public {
        address[] memory signers = new address[](1);
        signers[0] = address(0);

        vm.expectRevert("KernelAuthority: signer=0");
        new KernelAuthority(signers, 1);
    }

    function test_constructor_rejects_duplicate_signer() public {
        address[] memory signers = new address[](2);
        signers[0] = address(0x1234);
        signers[1] = address(0x1234);

        vm.expectRevert("KernelAuthority: signers not ordered");
        new KernelAuthority(signers, 1);
    }

    function test_getSigners_returns_sorted_signers() public view {
        address[] memory signers = authority.getSigners();
        assertEq(signers.length, 3, "signers length mismatch");
        assertEq(signers[0], s0.addr, "signer[0] mismatch");
        assertEq(signers[1], s1.addr, "signer[1] mismatch");
        assertEq(signers[2], s2.addr, "signer[2] mismatch");
    }

    function test_execute_transfers_value_to_target() public {
        vm.deal(address(authority), 1 ether);
        assertEq(address(receiver).balance, 0, "receiver should start empty");

        bytes memory data = bytes("");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecute(address(receiver), 0.25 ether, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s0, digest);
        sigs[1] = _signDigest(s1, digest);

        authority.execute(address(receiver), 0.25 ether, data, deadline, sigs);

        assertEq(address(receiver).balance, 0.25 ether, "receiver did not receive value");
        assertEq(receiver.receivedCount(), 1, "receiver not called");
        assertEq(receiver.lastValue(), 0.25 ether, "receiver lastValue mismatch");
        assertEq(authority.nonce(), nonceBefore + 1, "nonce not incremented");
    }

    function test_execute_rejects_invalid_signer_even_if_ordered() public {
        address[] memory signers = new address[](2);
        signers[0] = s0.addr;
        signers[1] = s2.addr;
        KernelAuthority a = new KernelAuthority(signers, 2);

        bytes memory data = abi.encodeWithSignature("doesNotMatter()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = a.nonce();

        bytes32 digest = a.hashExecute(address(receiver), 0, data, nonceBefore, deadline);

        // Signatures are in increasing-address order: s0 then s1, but s1 is not a signer in this authority.
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s0, digest);
        sigs[1] = _signDigest(s1, digest);

        vm.expectRevert("KernelAuthority: invalid signer");
        a.execute(address(receiver), 0, data, deadline, sigs);
    }

    function test_execute_rejects_duplicate_signatures() public {
        bytes memory data = abi.encodeWithSignature("doesNotMatter()");
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecute(address(receiver), 0, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s0, digest);
        sigs[1] = _signDigest(s0, digest);

        vm.expectRevert("KernelAuthority: signers not ordered");
        authority.execute(address(receiver), 0, data, deadline, sigs);
    }

    function test_executeBatch_rejects_empty_batch() public {
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory data = new bytes[](0);
        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert("KernelAuthority: empty batch");
        authority.executeBatch(targets, values, data, block.timestamp + 3600, sigs);
    }

    function test_executeBatch_rejects_length_mismatch() public {
        address[] memory targets = new address[](1);
        targets[0] = address(receiver);

        uint256[] memory values = new uint256[](2);
        values[0] = 0;
        values[1] = 0;

        bytes[] memory data = new bytes[](1);
        data[0] = bytes("");

        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert("KernelAuthority: length mismatch");
        authority.executeBatch(targets, values, data, block.timestamp + 3600, sigs);
    }

    function test_executeBatch_rejects_expired_deadline() public {
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);
        bytes[] memory sigs = new bytes[](0);

        targets[0] = address(receiver);
        values[0] = 0;
        data[0] = bytes("");

        uint256 deadline = block.timestamp + 1;
        vm.warp(deadline + 1);

        vm.expectRevert("KernelAuthority: expired");
        authority.executeBatch(targets, values, data, deadline, sigs);
    }

    function test_execute_reverts_when_setConfig_is_invalid() public {
        address[] memory badSigners = new address[](1);
        badSigners[0] = s0.addr;

        bytes memory data = abi.encodeCall(KernelAuthority.setConfig, (badSigners, 0));
        uint256 deadline = block.timestamp + 3600;
        uint256 nonceBefore = authority.nonce();

        bytes32 digest = authority.hashExecute(address(authority), 0, data, nonceBefore, deadline);

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(s0, digest);
        sigs[1] = _signDigest(s1, digest);

        vm.expectRevert("KernelAuthority: bad threshold");
        authority.execute(address(authority), 0, data, deadline, sigs);
    }

    function _signDigest(Signer memory signer, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sort3(Signer memory a, Signer memory b, Signer memory c) private pure returns (Signer[3] memory) {
        Signer[3] memory s = [a, b, c];
        if (s[0].addr > s[1].addr) {
            (s[0], s[1]) = (s[1], s[0]);
        }
        if (s[1].addr > s[2].addr) {
            (s[1], s[2]) = (s[2], s[1]);
        }
        if (s[0].addr > s[1].addr) {
            (s[0], s[1]) = (s[1], s[0]);
        }
        return s;
    }
}
