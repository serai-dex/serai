//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./ReentrancyGuard.sol";
import "./Schnorr.sol";

contract Router is Schnorr, ReentrancyGuard {
    // contract owner
    address public owner;

    // nonce is incremented for each batch of transactions executed
    uint256 public nonce; 

    // fixed parity for the public keys used in this contract
    uint8 constant public KEY_PARITY = 27;

    // current aggregated validator public key's x-coordinate
    // note: this key must always use the fixed parity defined above
    bytes32 public publicKey;

    struct RTransaction {
        address to;
        uint256 value;
        uint256 gas;
        bytes data;
    }

    struct RSignature {
        bytes32 e;
        bytes32 s;
    }

    // success is a uint256 representing a bitfield of transaction successes
    event Executed(uint256 nonce, uint256 success);

    // error types
    error Unauthorized();
    error PublicKeyAlreadySet();
    error VerificationError();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if(msg.sender != owner) revert Unauthorized();
        _;
    }

    // setPublicKey can be called by the contract owner to set the current public key,
    // only if the public key has not been set.
    function setPublicKey(
        bytes32 _publicKey
    ) public onlyOwner {
        if(publicKey != 0) revert PublicKeyAlreadySet();
        publicKey = _publicKey;
    }

    // updatePublicKey validates the given Schnorr signature against the current public key,
    // and if successful, updates the contract's public key to the given one.
    function updatePublicKey(
       bytes32 _publicKey,
        RSignature memory sig
    ) public {
        bytes32 message = keccak256(abi.encodePacked(KEY_PARITY, _publicKey));
        if (!verify(KEY_PARITY, publicKey, message, sig.e, sig.s)) revert VerificationError();
        publicKey = _publicKey;
    }

    // execute accepts a list of transactions to execute as well as a Schnorr signature.
    // if signature verification passes, the given transactions are executed.
    // if signature verification fails, this function will revert.
    // if any of the executed transactions fail, this function will return false but *not* revert.
    // if all the executed transactions succeed, this function returns true.
    function execute(
        RTransaction[] calldata transactions, 
        RSignature memory sig
    ) public nonReentrant returns (bool) {
        bytes32 message = keccak256(abi.encode(nonce, transactions));
        if (!verify(KEY_PARITY, publicKey, message, sig.e, sig.s)) revert VerificationError();

        uint256 successes;

        for(uint256 i = 0; i < transactions.length; i++) {
            (bool success, ) = transactions[i].to.call{value: transactions[i].value, gas: transactions[i].gas}(
                transactions[i].data
            );
            assembly {
                successes := or(successes, shl(i, success))
            }
        }

        emit Executed(nonce, successes);
        nonce++;
        return successes != 0;
    }
}
