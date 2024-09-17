// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

import "../Schnorr.sol";

contract TestSchnorr {
  function verify(bytes32 public_key, bytes calldata message, bytes32 c, bytes32 s)
    external
    pure
    returns (bool)
  {
    return Schnorr.verify(public_key, message, c, s);
  }
}
