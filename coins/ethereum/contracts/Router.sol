// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";

contract Router {
  // Nonce is incremented for each batch of transactions executed
  uint256 public nonce;

  // Current public key's x-coordinate
  // This key must always have the parity defined within the Schnorr contract
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
  error AlreadyInitialized();
  error InvalidKey();
  error InvalidSignature();
  error TooManyTransactions();

  constructor() {}

  // TODO: Limit to a MuSig of the genesis validators
  function initialize(bytes32 _seraiKey) external {
    if (seraiKey != 0) revert AlreadyInitialized();
    if (
      (_seraiKey == bytes32(0)) ||
      ((bytes32(uint256(_seraiKey) % Schnorr.Q)) != _seraiKey)
    ) {
      revert InvalidKey();
    }
    seraiKey = _seraiKey;
  }

  // updateSeraiKey validates the given Schnorr signature against the current
  // public key, and if successful, updates the contract's public key to the
  // given one.
  function updateSeraiKey(
    bytes32 _seraiKey,
    Signature memory sig
  ) public {
    if (
      (_seraiKey == bytes32(0)) ||
      ((bytes32(uint256(_seraiKey) % Schnorr.Q)) != _seraiKey)
    ) {
      revert InvalidKey();
    }

    bytes memory message =
      abi.encodePacked("updateSeraiKey", block.chainid, _seraiKey);
    if (!Schnorr.verify(seraiKey, message, sig.c, sig.s)) {
      revert InvalidSignature();
    }
    seraiKey = _seraiKey;
  }

  // execute accepts a list of transactions to execute as well as a signature.
  // if signature verification passes, the given transactions are executed.
  // if signature verification fails, this function will revert.
  function execute(
    OutInstruction[] calldata transactions,
    Signature memory sig
  ) public {
    if (transactions.length > 256) revert TooManyTransactions();

    bytes memory message =
      abi.encode("execute", block.chainid, nonce, transactions);
    // This prevents re-entrancy from causing double spends yet does allow
    // out-of-order execution via re-entrancy
    nonce++;
    if (!Schnorr.verify(seraiKey, message, sig.c, sig.s)) {
      revert InvalidSignature();
    }

    uint256 successes;
    for (uint256 i = 0; i < transactions.length; i++) {
      (bool success, ) =
        transactions[i].to.call{
          value: transactions[i].value,
          gas: 200_000
        }(transactions[i].data);

      assembly {
        successes := or(successes, shl(i, success))
      }
    }
    emit Executed(nonce, keccak256(message), successes);
  }
}
