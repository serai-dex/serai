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

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
  alloy_core::primitives::keccak256(data).into()
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  <Scalar as Reduce<KU256>>::reduce_bytes(&keccak256(data).into())
}

pub(crate) fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  **Address::from_raw_public_key(&encoded_point.as_ref()[1 .. 65])
}

/// Deterministically sign a transaction.
///
/// This function panics if passed a transaction with a non-None chain ID.
pub fn deterministically_sign(tx: &TxLegacy) -> Signed<TxLegacy> {
  assert!(
    tx.chain_id.is_none(),
    "chain ID was Some when deterministically signing a TX (causing a non-deterministic signer)"
  );

  let sig_hash = tx.signature_hash().0;
  let mut r = hash_to_scalar(&[sig_hash.as_slice(), b"r"].concat());
  let mut s = hash_to_scalar(&[sig_hash.as_slice(), b"s"].concat());
  loop {
    let r_bytes: [u8; 32] = r.to_repr().into();
    let s_bytes: [u8; 32] = s.to_repr().into();
    let v = Parity::NonEip155(false);
    let signature =
      AlloySignature::from_scalars_and_parity(r_bytes.into(), s_bytes.into(), v).unwrap();
    let tx = tx.clone().into_signed(signature);
    if tx.recover_signer().is_ok() {
      return tx;
    }

    // Re-hash until valid
    r = hash_to_scalar(r_bytes.as_ref());
    s = hash_to_scalar(s_bytes.as_ref());
  }
}

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
