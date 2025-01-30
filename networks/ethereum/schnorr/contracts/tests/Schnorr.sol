// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

import "../Schnorr.sol";

/// @title A thin wrapper around the library for verifying Schnorr signatures to test it with
/// @author Luke Parker <lukeparker5132@gmail.com>
/// @author Elizabeth Binks <elizabethjbinks@gmail.com>
contract TestSchnorr {
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
  function verify(bytes32 publicKey, bytes calldata message, bytes32 c, bytes32 s)
    external
    pure
    returns (bool)
  {
    return Schnorr.verify(publicKey, keccak256(message), c, s);
  }
}
