pragma solidity ^0.8.24;

/// @dev Minimal Foundry cheatcodes interface (no external dependencies).
interface Vm {
    function prank(address) external;
    function warp(uint256) external;
    function expectRevert(bytes calldata) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

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
}
