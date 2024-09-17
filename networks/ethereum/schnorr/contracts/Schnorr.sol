// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

// See https://github.com/noot/schnorr-verify for implementation details
library Schnorr {
  // secp256k1 group order
  uint256 private constant Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  // We fix the key to have:
  // 1) An even y-coordinate
  // 2) An x-coordinate < Q
  uint8 private constant KEY_PARITY = 27;

  // px := public key x-coordinate, where the public key has an even y-coordinate
  // message := the message signed
  // c := Schnorr signature challenge
  // s := Schnorr signature solution
  function verify(bytes32 px, bytes memory message, bytes32 c, bytes32 s)
    internal
    pure
    returns (bool)
  {
    // ecrecover = (m, v, r, s) -> key
    // We instead pass the following to obtain the nonce (not the key)
    // Then we hash it and verify it matches the challenge
    bytes32 sa = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
    bytes32 ca = bytes32(Q - mulmod(uint256(c), uint256(px), Q));

    /*
      The ecrecover precompile checks `r` and `s` (`px` and `ca`) are non-zero,
      banning the two keys with zero for their x-coordinate and zero challenge.
      Each has negligible probability of occuring (assuming zero x-coordinates
      are even on-curve in the first place).

      `sa` is not checked to be non-zero yet it does not need to be. The inverse
      of it is never taken.
    */
    address R = ecrecover(sa, KEY_PARITY, px, ca);
    // The ecrecover failed
    if (R == address(0)) return false;

    // Check the signature is correct by rebuilding the challenge
    return c == keccak256(abi.encodePacked(R, px, message));
  }
}
