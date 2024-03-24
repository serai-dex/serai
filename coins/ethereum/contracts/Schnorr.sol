// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

// see https://github.com/noot/schnorr-verify for implementation details
contract Schnorr {
  // secp256k1 group order
  uint256 constant public Q =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  error InvalidSOrA();
  error InvalidSignature();

  // parity := public key y-coord parity (27 or 28)
  // px := public key x-coord
  // message := 32-byte hash of the message
  // c := schnorr signature challenge
  // s := schnorr signature
  function verify(
    uint8 parity,
    bytes32 px,
    bytes32 message,
    bytes32 c,
    bytes32 s
  ) public view returns (bool) {
    // ecrecover = (m, v, r, s);
    bytes32 sa = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
    bytes32 ca = bytes32(Q - mulmod(uint256(c), uint256(px), Q));

    if (sa == 0) revert InvalidSOrA();
    // the ecrecover precompile implementation checks that the `r` and `s`
    // inputs are non-zero (in this case, `px` and `ca`), thus we don't need to
    // check if they're zero.
    address R = ecrecover(sa, parity, px, ca);
    if (R == address(0)) revert InvalidSignature();
    return c == keccak256(
      abi.encodePacked(R, uint8(parity), px, block.chainid, message)
    );
  }
}
