// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "../../../contracts/Schnorr.sol";

contract TestSchnorr {
  function verify(
    bytes32 px,
    bytes calldata message,
    bytes32 c,
    bytes32 s
  ) external pure returns (bool) {
    return Schnorr.verify(px, message, c, s);
  }
}
