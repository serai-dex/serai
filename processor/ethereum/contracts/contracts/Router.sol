// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./IERC20.sol";

import "./Schnorr.sol";
import "./Sandbox.sol";

contract Router {
  // Nonce is incremented for each batch of transactions executed/key update
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

  event SeraiKeyUpdated(
    uint256 indexed nonce,
    bytes32 indexed key,
    Signature signature
  );
  event InInstruction(
    address indexed from,
    address indexed coin,
    uint256 amount,
    bytes instruction
  );
  // success is a uint256 representing a bitfield of transaction successes
  event Executed(
    uint256 indexed nonce,
    bytes32 indexed batch,
    uint256 success,
    Signature signature
  );

  // error types
  error InvalidKey();
  error InvalidSignature();
  error InvalidAmount();
  error FailedTransfer();
  error TooManyTransactions();

  modifier _updateSeraiKeyAtEndOfFn(
    uint256 _nonce,
    bytes32 key,
    Signature memory sig
  ) {
    if (
      (key == bytes32(0)) ||
      ((bytes32(uint256(key) % Schnorr.Q)) != key)
    ) {
      revert InvalidKey();
    }

    _;

    seraiKey = key;
    emit SeraiKeyUpdated(_nonce, key, sig);
  }

  constructor(bytes32 _seraiKey) _updateSeraiKeyAtEndOfFn(
    0,
    _seraiKey,
    Signature({ c: bytes32(0), s: bytes32(0) })
  ) {
    nonce = 1;
  }

  // updateSeraiKey validates the given Schnorr signature against the current
  // public key, and if successful, updates the contract's public key to the
  // given one.
  function updateSeraiKey(
    bytes32 _seraiKey,
    Signature calldata sig
  ) external _updateSeraiKeyAtEndOfFn(nonce, _seraiKey, sig) {
    bytes memory message =
      abi.encodePacked("updateSeraiKey", block.chainid, nonce, _seraiKey);
    nonce++;

    if (!Schnorr.verify(seraiKey, message, sig.c, sig.s)) {
      revert InvalidSignature();
    }
  }

  function inInstruction(
    address coin,
    uint256 amount,
    bytes memory instruction
  ) external payable {
    if (coin == address(0)) {
      if (amount != msg.value) {
        revert InvalidAmount();
      }
    } else {
      (bool success, bytes memory res) =
        address(coin).call(
          abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            msg.sender,
            address(this),
            amount
          )
        );

      // Require there was nothing returned, which is done by some non-standard
      // tokens, or that the ERC20 contract did in fact return true
      bool nonStandardResOrTrue =
        (res.length == 0) || abi.decode(res, (bool));
      if (!(success && nonStandardResOrTrue)) {
        revert FailedTransfer();
      }
    }

    /*
    Due to fee-on-transfer tokens, emitting the amount directly is frowned upon.
    The amount instructed to transfer may not actually be the amount
    transferred.

    If we add nonReentrant to every single function which can effect the
    balance, we can check the amount exactly matches. This prevents transfers of
    less value than expected occurring, at least, not without an additional
    transfer to top up the difference (which isn't routed through this contract
    and accordingly isn't trying to artificially create events).

    If we don't add nonReentrant, a transfer can be started, and then a new
    transfer for the difference can follow it up (again and again until a
    rounding error is reached). This contract would believe all transfers were
    done in full, despite each only being done in part (except for the last
    one).

    Given fee-on-transfer tokens aren't intended to be supported, the only
    token planned to be supported is Dai and it doesn't have any fee-on-transfer
    logic, fee-on-transfer tokens aren't even able to be supported at this time,
    we simply classify this entire class of tokens as non-standard
    implementations which induce undefined behavior. It is the Serai network's
    role not to add support for any non-standard implementations.
    */
    emit InInstruction(msg.sender, coin, amount, instruction);
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
    uint256 executed_with_nonce = nonce;
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
          // TODO: Have the Call specify the gas up front
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
    emit Executed(
      executed_with_nonce,
      keccak256(message),
      successes,
      sig
    );
  }
}
