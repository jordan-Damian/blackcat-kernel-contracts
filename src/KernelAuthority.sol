pragma solidity ^0.8.24;

/// @notice Minimal EIP-712 threshold signer authority (multi-device by design).
/// @dev Skeleton contract (not audited, not production-ready).
contract KernelAuthority {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("BlackCatKernelAuthority"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");

    uint256 private constant SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    mapping(address => bool) public isSigner;
    address[] private signers;

    uint256 public threshold;
    uint256 public nonce;

    event Executed(address indexed target, uint256 value, bytes32 dataHash, uint256 nonce, address indexed executor);
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
        bytes32 structHash = keccak256(
            abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce_, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function execute(address target, uint256 value, bytes calldata data, uint256 deadline, bytes[] calldata signatures)
        external
        returns (bytes memory)
    {
        require(block.timestamp <= deadline, "KernelAuthority: expired");

        uint256 nonce_ = nonce;
        bytes32 structHash = keccak256(
            abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce_, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        _checkSignatures(digest, signatures);
        nonce = nonce_ + 1;

        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            _revertWith(ret);
        }

        emit Executed(target, value, keccak256(data), nonce_, msg.sender);
        return ret;
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
        require(signature.length == 65, "KernelAuthority: bad signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
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
}

