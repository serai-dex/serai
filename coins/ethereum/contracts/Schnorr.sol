// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

// see https://github.com/noot/schnorr-verify for implementation details
library Schnorr {
  // secp256k1 group order
  uint256 constant public Q =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  // Fixed parity for the public keys used in this contract
  // This avoids spending a word passing the parity in a similar style to
  // Bitcoin's Taproot
  uint8 constant public KEY_PARITY = 27;

  error InvalidSOrA();
  error MalformedSignature();

  // px := public key x-coord, where the public key has a parity of KEY_PARITY
  // message := 32-byte hash of the message
  // c := schnorr signature challenge
  // s := schnorr signature
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

    // For safety, we want each input to ecrecover to be 0 (sa, px, ca)
    // The ecreover precomple checks `r` and `s` (`px` and `ca`) are non-zero
    // That leaves us to check `sa` are non-zero
    if (sa == 0) revert InvalidSOrA();
    address R = ecrecover(sa, KEY_PARITY, px, ca);
    if (R == address(0)) revert MalformedSignature();

    // Check the signature is correct by rebuilding the challenge
    return c == keccak256(abi.encodePacked(R, px, message));
  }
}

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
