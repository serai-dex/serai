// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

/// @title A library for verifying Schnorr signatures
/// @author Luke Parker <lukeparker@serai.exchange>
/// @author Elizabeth Binks <elizabethjbinks@gmail.com>
/// @notice Verifies a Schnorr signature for a specified public key
/**
 * @dev This contract is not complete (in the cryptographic sense). Only a subset of potential
 *  public keys are representable here.
 *
 *   See https://github.com/serai-dex/serai/blob/next/networks/ethereum/schnorr/src/tests/premise.rs
 *   for implementation details
 */
// TODO: Pin above link to a specific branch/commit once `next` is merged into `develop`
library Schnorr {
  // secp256k1 group order
  uint256 private constant Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  // We fix the key to have:
  // 1) An even y-coordinate
  // 2) An x-coordinate < Q
  uint8 private constant KEY_PARITY = 27;

  /// @notice Verifies a Schnorr signature for the specified public key
  /**
   * @dev The y-coordinate of the public key is assumed to be even. The x-coordinate of the public
   *   key is assumed to be less than the order of secp256k1.
   *
   *   The challenge is calculated as `keccak256(abi.encodePacked(address(R), publicKey, message))`
   *   where `R` is the commitment to the Schnorr signature's nonce.
   */
  /// @param publicKey The x-coordinate of the public key
  /// @param message The (hash of the) message signed
  /// @param c The challenge for the Schnorr signature
  /// @param s The response to the challenge for the Schnorr signature
  /// @return If the signature is valid
  function verify(bytes32 publicKey, bytes32 message, bytes32 c, bytes32 s)
    internal
    pure
    returns (bool)
  {
    // ecrecover = (m, v, r, s) -> key
    // We instead pass the following to recover the Schnorr signature's nonce (not a public key)
    bytes32 sa = bytes32(Q - mulmod(uint256(s), uint256(publicKey), Q));
    bytes32 ca = bytes32(Q - mulmod(uint256(c), uint256(publicKey), Q));

    /*
      The ecrecover precompile checks `r` and `s` (`publicKey` and `ca`) are non-zero, banning the
      two keys with zero for their x-coordinate and zero challenges. Each already only had a
      negligible probability of occuring (assuming zero x-coordinates are even on-curve in the first
      place).

      `sa` is not checked to be non-zero yet it does not need to be. The inverse of it is never
      taken.
    */
    address R = ecrecover(sa, KEY_PARITY, publicKey, ca);
    // The ecrecover failed
    if (R == address(0)) return false;

    // Check the signature is correct by rebuilding the challenge
    return c == keccak256(abi.encodePacked(R, publicKey, message));
  }
}
