/*
 * SPDX-FileCopyrightText: 2025 Black Cat Academy s. r. o.
 * SPDX-License-Identifier: LicenseRef-BlackCat-Proprietary-1.0
 */

pragma solidity ^0.8.24;

/// @notice Minimal EIP-712 threshold signer authority (multi-device by design).
/// @dev Skeleton contract (not audited, not production-ready).
contract KernelAuthority {
    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatKernelAuthority"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");

    bytes32 private constant EXECUTE_BATCH_TYPEHASH = keccak256(
        "ExecuteBatch(bytes32 targetsHash,bytes32 valuesHash,bytes32 dataHashesHash,uint256 nonce,uint256 deadline)"
    );

    uint256 private constant SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant EIP2098_S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    mapping(address => bool) public isSigner;
    address[] private signers;

    uint256 public threshold;
    uint256 public nonce;

    event Executed(address indexed target, uint256 value, bytes32 dataHash, uint256 nonce, address indexed executor);
    event BatchExecuted(
        uint256 count,
        bytes32 targetsHash,
        bytes32 valuesHash,
        bytes32 dataHashesHash,
        uint256 nonce,
        address indexed executor
    );
    event ConfigChanged(uint256 threshold, address[] signers);

    constructor(address[] memory signers_, uint256 threshold_) {
        _setConfig(signers_, threshold_);
    }

    receive() external payable {}

    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function hashExecute(address target, uint256 value, bytes calldata data, uint256 nonce_, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce_, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function hashExecuteBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data,
        uint256 nonce_,
        uint256 deadline
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_BATCH_TYPEHASH,
                keccak256(abi.encode(targets)),
                keccak256(abi.encode(values)),
                _hashDataHashes(data),
                nonce_,
                deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function execute(address target, uint256 value, bytes calldata data, uint256 deadline, bytes[] calldata signatures)
        external
        returns (bytes memory)
    {
        require(block.timestamp <= deadline, "KernelAuthority: expired");
        require(target != address(0), "KernelAuthority: target=0");

        uint256 nonce_ = nonce;
        bytes32 structHash = keccak256(abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce_, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        _checkSignatures(digest, signatures);
        nonce = nonce_ + 1;

        // slither-disable-next-line arbitrary-send-eth
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            _revertWith(ret);
        }

        emit Executed(target, value, keccak256(data), nonce_, msg.sender);
        return ret;
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        require(block.timestamp <= deadline, "KernelAuthority: expired");

        uint256 count = targets.length;
        require(count != 0, "KernelAuthority: empty batch");
        require(values.length == count && data.length == count, "KernelAuthority: length mismatch");

        uint256 nonce_ = nonce;
        {
            bytes32 targetsHash = keccak256(abi.encode(targets));
            bytes32 valuesHash = keccak256(abi.encode(values));
            bytes32 dataHashesHash = _hashDataHashes(data);

            bytes32 structHash = keccak256(
                abi.encode(EXECUTE_BATCH_TYPEHASH, targetsHash, valuesHash, dataHashesHash, nonce_, deadline)
            );
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
            _checkSignatures(digest, signatures);
            nonce = nonce_ + 1;

            emit BatchExecuted(count, targetsHash, valuesHash, dataHashesHash, nonce_, msg.sender);
        }

        for (uint256 i = 0; i < count; i++) {
            address target = targets[i];
            require(target != address(0), "KernelAuthority: target=0");
            // slither-disable-next-line arbitrary-send-eth
            (bool ok, bytes memory ret) = target.call{value: values[i]}(data[i]);
            if (!ok) {
                _revertWith(ret);
            }
        }
    }

    /// @notice EIP-1271 signature validator for tooling that expects contract-based signing.
    /// @dev Encoding: `signature` is ABI-encoded `bytes[]` with signer signatures (65 bytes each) in ascending address order.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        bytes[] memory sigs = abi.decode(signature, (bytes[]));

        uint256 required = threshold;
        if (sigs.length < required) {
            return bytes4(0);
        }

        address last = address(0);
        for (uint256 i = 0; i < required; i++) {
            address signer = _recover(hash, sigs[i]);
            if (!isSigner[signer] || signer <= last) {
                return bytes4(0);
            }
            last = signer;
        }

        return EIP1271_MAGICVALUE;
    }

    function setConfig(address[] calldata newSigners, uint256 newThreshold) external {
        require(msg.sender == address(this), "KernelAuthority: only self");
        _setConfig(newSigners, newThreshold);
    }

    function _setConfig(address[] memory newSigners, uint256 newThreshold) private {
        require(newSigners.length != 0, "KernelAuthority: no signers");
        require(newThreshold != 0 && newThreshold <= newSigners.length, "KernelAuthority: bad threshold");

        address[] memory oldSigners = signers;
        for (uint256 i = 0; i < oldSigners.length; i++) {
            isSigner[oldSigners[i]] = false;
        }

        address last = address(0);
        for (uint256 i = 0; i < newSigners.length; i++) {
            address signer = newSigners[i];
            require(signer != address(0), "KernelAuthority: signer=0");
            require(signer > last, "KernelAuthority: signers not ordered");
            require(!isSigner[signer], "KernelAuthority: duplicate signer");
            isSigner[signer] = true;
            last = signer;
        }

        signers = newSigners;
        threshold = newThreshold;
        emit ConfigChanged(newThreshold, newSigners);
    }

    function _checkSignatures(bytes32 digest, bytes[] calldata signatures) private view {
        uint256 required = threshold;
        require(signatures.length >= required, "KernelAuthority: insufficient signatures");

        address last = address(0);
        for (uint256 i = 0; i < required; i++) {
            address signer = _recover(digest, signatures[i]);
            require(isSigner[signer], "KernelAuthority: invalid signer");
            require(signer > last, "KernelAuthority: signers not ordered");
            last = signer;
        }
    }

    function _recover(bytes32 digest, bytes memory signature) private pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length == 65) {
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }

            if (v < 27) {
                v += 27;
            }
        } else if (signature.length == 64) {
            bytes32 vs;
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }

            s = bytes32(uint256(vs) & EIP2098_S_MASK);
            v = uint8((uint256(vs) >> 255) + 27);
        } else {
            revert("KernelAuthority: bad signature length");
        }
        require(v == 27 || v == 28, "KernelAuthority: bad v");
        require(uint256(s) <= SECP256K1N_HALF, "KernelAuthority: bad s");

        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "KernelAuthority: bad signature");
        return signer;
    }

    function _revertWith(bytes memory data) private pure {
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }

    function _hashDataHashes(bytes[] calldata data) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            hashes[i] = keccak256(data[i]);
        }
        return keccak256(abi.encode(hashes));
    }
}
