/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {BlackCatInstanceControllerV1 as InstanceController} from "../src/InstanceController.sol";
import {BlackCatInstanceFactoryV1 as InstanceFactory} from "../src/InstanceFactory.sol";

contract Eip1271ExactSigner {
    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;

    address public immutable admin;
    bytes32 public expectedHash;
    bytes32 public expectedSigHash;

    constructor() {
        admin = msg.sender;
    }

    function setExpected(bytes32 hash, bytes32 sigHash) external {
        require(msg.sender == admin, "Eip1271ExactSigner: only admin");
        expectedHash = hash;
        expectedSigHash = sigHash;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (hash == expectedHash && keccak256(signature) == expectedSigHash) {
            return EIP1271_MAGICVALUE;
        }
        return bytes4(0);
    }
}

contract InstanceControllerSignatureResolutionTest is TestBase {
    bytes32 private constant SET_PAUSED_TYPEHASH =
        keccak256("SetPaused(bool expectedPaused,bool newPaused,uint256 nonce,uint256 deadline)");

    function test_setPausedAuthorized_accepts_eip1271_signature_even_if_malformed_ecdsa_for_root() public {
        InstanceFactory factory = new InstanceFactory(address(0));

        uint256 rootPk = 0xA11CE;
        address root = vm.addr(rootPk);
        address upgrader = address(0x2222222222222222222222222222222222222222);

        Eip1271ExactSigner emergencySigner = new Eip1271ExactSigner();

        bytes32 genesisRoot = keccak256("genesis-root");
        bytes32 genesisUriHash = keccak256("uri");
        bytes32 genesisPolicyHash = keccak256("policy");

        address instance = factory.createInstance(
            root, upgrader, address(emergencySigner), genesisRoot, genesisUriHash, genesisPolicyHash
        );
        InstanceController controller = InstanceController(instance);

        bool expectedPaused = false;
        bool newPaused = true;
        uint256 deadline = block.timestamp + 1 hours;

        // Deliberately malformed as ECDSA for the root signer:
        // v=5 -> v+27=32 -> invalid for strict ECDSA recover.
        bytes memory signature = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(5));

        bytes32 structHash =
            keccak256(abi.encode(SET_PAUSED_TYPEHASH, expectedPaused, newPaused, controller.pauseNonce(), deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", controller.domainSeparator(), structHash));

        emergencySigner.setExpected(digest, keccak256(signature));

        controller.setPausedAuthorized(expectedPaused, newPaused, deadline, signature);

        assertTrue(controller.paused(), "pause should succeed via EIP-1271 signer");
        assertEq(controller.pauseNonce(), 1, "pause nonce should increment");
    }
}

