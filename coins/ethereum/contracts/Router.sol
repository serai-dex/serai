//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./ReentrancyGuard.sol";
import "./Schnorr.sol";

contract Router is Schnorr, ReentrancyGuard {
    // contract owner
    address owner;

    // nonce is incremented for each batch of transactions executed
    uint256 nonce; 

    // prevents re-entrancy
    uint8 internal locked;

    struct PublicKey {
        uint8 parity;
        bytes32 px;
    }

    // current aggregated validator public key 
    PublicKey publicKey;

    struct Transaction {
        address to;
        uint256 value;
        uint256 gas;
        bytes data;
    }

    struct Signature {
        bytes32 e;
        bytes32 s;
    }

    event Executed(uint256 nonce, uint256 index, bool success);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "must be called by the contract owner");
        _;
    }

    function getNonce() external view returns (uint256) {
        return nonce;
    }

    // setPublicKey can be called by the contract owner to set the current public key,
    // only if the public key has not been set.
    function setPublicKey(
        PublicKey memory _publicKey
    ) public onlyOwner {
        require(publicKey.px == 0, "public key has already been set");
        publicKey.parity = _publicKey.parity;
        publicKey.px = _publicKey.px;
    }

    // updatePublicKey validates the given Schnorr signature against the current public key,
    // and if successful, updates the contract's public key to the given one.
    function updatePublicKey(
        PublicKey memory _publicKey,
        Signature memory sig
    ) public {
        bytes32 message = keccak256(abi.encode(_publicKey.parity, _publicKey.px));
        require(verify(publicKey.parity, publicKey.px, message, sig.s, sig.e), "failed to verify signature");
        publicKey = _publicKey;
    }

    // execute accepts a list of transactions to execute as well as a Schnorr signature.
    // if signature verification passes, the given transactions are executed.
    // if signature verification fails, this function will revert.
    // if any of the executed transactions fail, this function will return false but *not* revert.
    // if all the executed transactions succeed, this function returns true.
    function execute(
        Transaction[] calldata transactions, 
        Signature memory sig
    ) public nonReentrant returns (bool) {
        bytes32 message = keccak256(abi.encode(nonce, transactions));
        require(verify(publicKey.parity, publicKey.px, message, sig.s, sig.e), "failed to verify signature");
        bool allOk = true;
        for(uint256 i = 0; i < transactions.length; i++) {
            (bool success, ) = transactions[i].to.call{value: transactions[i].value, gas: transactions[i].gas}(
                transactions[i].data
            );
            emit Executed(nonce, i, success);
            allOk = success && allOk;
        }
        nonce++;
        return allOk;
    }
}
