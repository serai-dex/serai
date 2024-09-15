// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

// See https://github.com/noot/schnorr-verify for implementation details
library Schnorr {
  // secp256k1 group order
  uint256 constant private Q =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  // We fix the key to have an even y coordinate to save a word when verifying
  // signatures. This is comparable to Bitcoin Taproot's encoding of keys
  uint8 constant private KEY_PARITY = 27;

  // px := public key x-coordinate, where the public key has an even y-coordinate
  // message := the message signed
  // c := Schnorr signature challenge
  // s := Schnorr signature solution
  function verify(
    bytes32 px,
    bytes memory message,
    bytes32 c,
    bytes32 s
  ) internal pure returns (bool) {
    // ecrecover = (m, v, r, s) -> key
    // We instead pass the following to obtain the nonce (not the key)
    // Then we hash it and verify it matches the challenge
    bytes32 sa = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
    bytes32 ca = bytes32(Q - mulmod(uint256(c), uint256(px), Q));

    // For safety, we want each input to ecrecover to not be 0 (sa, px, ca)
    // The ecrecover precompile checks `r` and `s` (`px` and `ca`) are non-zero
    // That leaves us to check `sa` are non-zero
    if (sa == 0) return false;
    address R = ecrecover(sa, KEY_PARITY, px, ca);
    if (R == address(0)) return false;

    // Check the signature is correct by rebuilding the challenge
    return c == keccak256(abi.encodePacked(R, px, message));
  }
}
