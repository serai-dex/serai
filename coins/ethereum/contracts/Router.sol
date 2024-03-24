// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";

contract Router is Schnorr {
  // Contract initializer
  // TODO: Replace with a MuSig of the genesis validators
  address public initializer;

  // Nonce is incremented for each batch of transactions executed
  uint256 public nonce;

  // fixed parity for the public keys used in this contract
  uint8 constant public KEY_PARITY = 27;

  // current public key's x-coordinate
  // note: this key must always use the fixed parity defined above
  bytes32 public seraiKey;

  struct OutInstruction {
    address to;
    uint256 value;
    bytes data;
  }

  struct Signature {
    bytes32 c;
    bytes32 s;
  }

  // success is a uint256 representing a bitfield of transaction successes
  event Executed(uint256 nonce, bytes32 batch, uint256 success);

  // error types
  error NotInitializer();
  error AlreadyInitialized();
  error InvalidKey();
  error TooManyTransactions();

  constructor() {
    initializer = msg.sender;
  }

  // initSeraiKey can be called by the contract initializer to set the first
  // public key, only if the public key has yet to be set.
  function initSeraiKey(bytes32 _seraiKey) external {
    if (msg.sender != initializer) revert NotInitializer();
    if (seraiKey != 0) revert AlreadyInitialized();
    if (_seraiKey == bytes32(0)) revert InvalidKey();
    seraiKey = _seraiKey;
  }

  // updateSeraiKey validates the given Schnorr signature against the current public key,
  // and if successful, updates the contract's public key to the given one.
  function updateSeraiKey(
    bytes32 _seraiKey,
    Signature memory sig
  ) public {
    if (_seraiKey == bytes32(0)) revert InvalidKey();
    bytes32 message = keccak256(abi.encodePacked("updateSeraiKey", _seraiKey));
    if (!verify(KEY_PARITY, seraiKey, message, sig.c, sig.s)) revert InvalidSignature();
    seraiKey = _seraiKey;
  }

  // execute accepts a list of transactions to execute as well as a Schnorr signature.
  // if signature verification passes, the given transactions are executed.
  // if signature verification fails, this function will revert.
  function execute(
    OutInstruction[] calldata transactions,
    Signature memory sig
  ) public {
    if (transactions.length > 256) revert TooManyTransactions();

    bytes32 message = keccak256(abi.encode("execute", nonce, transactions));
    // This prevents re-entrancy from causing double spends yet does allow
    // out-of-order execution via re-entrancy
    nonce++;
    if (!verify(KEY_PARITY, seraiKey, message, sig.c, sig.s)) revert InvalidSignature();

    uint256 successes;
    for(uint256 i = 0; i < transactions.length; i++) {
      (bool success, ) = transactions[i].to.call{value: transactions[i].value, gas: 200_000}(transactions[i].data);
      assembly {
        successes := or(successes, shl(i, success))
      }
    }
    emit Executed(nonce, message, successes);
  }
}
