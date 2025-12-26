/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

/// @dev Minimal Foundry cheatcodes interface (no external dependencies).
interface Vm {
    function prank(address) external;
    function warp(uint256) external;
    function deal(address who, uint256 newBalance) external;
    function expectRevert() external;
    function expectRevert(bytes calldata) external;
    function assume(bool) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant SECP256K1N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function assertTrue(bool v, string memory message) internal pure {
        require(v, message);
    }

    function assertEq(address a, address b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(bytes32 a, bytes32 b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(uint256 a, uint256 b, string memory message) internal pure {
        require(a == b, message);
    }

    function toEip2098Signature(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes memory) {
        uint256 vs = uint256(s);
        if (v == 28) {
            vs |= (1 << 255);
        }
        return abi.encodePacked(r, bytes32(vs));
    }

    function toMalleableHighSSignature(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes memory) {
        uint256 altS = SECP256K1N - uint256(s);
        uint8 altV = v == 27 ? 28 : 27;
        return abi.encodePacked(r, bytes32(altS), altV);
    }
}
