// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";
import "./Sandbox.sol";

contract Router {
  // Nonce is incremented for each batch of transactions executed
  uint256 public nonce;

  // Current public key's x-coordinate
  // This key must always have the parity defined within the Schnorr contract
  bytes32 public seraiKey;

  struct OutInstruction {
    address to;
    Call[] calls;

    uint256 value;
  }

  struct Signature {
    bytes32 c;
    bytes32 s;
  }

  event SeraiKeyUpdated(bytes32 key);
  // success is a uint256 representing a bitfield of transaction successes
  event Executed(uint256 nonce, bytes32 batch, uint256 success);

  // error types
  error InvalidKey();
  error InvalidSignature();
  error TooManyTransactions();

  modifier _updateSeraiKey(bytes32 key) {
    if (
      (key == bytes32(0)) ||
      ((bytes32(uint256(key) % Schnorr.Q)) != key)
    ) {
      revert InvalidKey();
    }

    _;

    seraiKey = key;
    emit SeraiKeyUpdated(key);
  }

  constructor(bytes32 _seraiKey) _updateSeraiKey(_seraiKey) {}

  // updateSeraiKey validates the given Schnorr signature against the current
  // public key, and if successful, updates the contract's public key to the
  // given one.
  function updateSeraiKey(
    bytes32 _seraiKey,
    Signature calldata sig
  ) external _updateSeraiKey(_seraiKey) {
    // TODO: If this updates to an old key, this can be replayed
    bytes memory message =
      abi.encodePacked("updateSeraiKey", block.chainid, _seraiKey);
    if (!Schnorr.verify(seraiKey, message, sig.c, sig.s)) {
      revert InvalidSignature();
    }
  }

  // execute accepts a list of transactions to execute as well as a signature.
  // if signature verification passes, the given transactions are executed.
  // if signature verification fails, this function will revert.
  function execute(
    OutInstruction[] calldata transactions,
    Signature calldata sig
  ) external {
    if (transactions.length > 256) {
      revert TooManyTransactions();
    }

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
      bool success;

      // If there are no calls, send to `to` the value
      if (transactions[i].calls.length == 0) {
        (success, ) = transactions[i].to.call{
          value: transactions[i].value,
          gas: 5_000
        }("");
      } else {
        // If there are calls, ignore `to`. Deploy a new Sandbox and proxy the
        // calls through that
        //
        // We could use a single sandbox in order to reduce gas costs, yet that
        // risks one person creating an approval that's hooked before another
        // user's intended action executes, in order to drain their coins
        //
        // While technically, that would be a flaw in the sandboxed flow, this
        // is robust and prevents such flaws from being possible
        //
        // We also don't want people to set state via the Sandbox and expect it
        // future available when anyone else could set a distinct value
        Sandbox sandbox = new Sandbox();
        (success, ) = address(sandbox).call{
          value: transactions[i].value,
          gas: 350_000
        }(
          abi.encodeWithSelector(
            Sandbox.sandbox.selector,
            transactions[i].calls
          )
        );
      }

      assembly {
        successes := or(successes, shl(i, success))
      }
    }
    emit Executed(nonce, keccak256(message), successes);
  }
}
