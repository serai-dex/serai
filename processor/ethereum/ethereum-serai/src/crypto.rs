use group::ff::PrimeField;
use k256::{
  elliptic_curve::{
    ops::Reduce,
    point::{AffineCoordinates, DecompressPoint},
    sec1::ToEncodedPoint,
  },
  AffinePoint, ProjectivePoint, Scalar, U256 as KU256,
};

use frost::{
  algorithm::{Hram, SchnorrSignature},
  curve::{Ciphersuite, Secp256k1},
};

pub use ethereum_schnorr_contract::*;

use alloy_core::primitives::{Parity, Signature as AlloySignature, Address};
use alloy_consensus::{SignableTransaction, Signed, TxLegacy};

/// The HRAm to use for the Schnorr Solidity library.
///
/// This will panic if the public key being signed for is not representable within the Schnorr
/// Solidity library.
#[derive(Clone, Default)]
pub struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    Signature::challenge(*R, &PublicKey::new(*A).unwrap(), m)
  }
}
