#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use group::ff::PrimeField;
use k256::{elliptic_curve::ops::Reduce, U256, Scalar};

use alloy_core::primitives::{Parity, Signature};
use alloy_consensus::{SignableTransaction, Signed, TxLegacy};

/// The Keccak256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  alloy_core::primitives::keccak256(data.as_ref()).into()
}

/// Deterministically sign a transaction.
///
/// This function panics if passed a transaction with a non-None chain ID.
pub fn deterministically_sign(tx: &TxLegacy) -> Signed<TxLegacy> {
  pub fn hash_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&keccak256(data).into())
  }

  assert!(
    tx.chain_id.is_none(),
    "chain ID was Some when deterministically signing a TX (causing a non-deterministic signer)"
  );

  let sig_hash = tx.signature_hash().0;
  let mut r = hash_to_scalar([sig_hash.as_slice(), b"r"].concat());
  let mut s = hash_to_scalar([sig_hash.as_slice(), b"s"].concat());
  loop {
    // Create the signature
    let r_bytes: [u8; 32] = r.to_repr().into();
    let s_bytes: [u8; 32] = s.to_repr().into();
    let v = Parity::NonEip155(false);
    let signature = Signature::from_scalars_and_parity(r_bytes.into(), s_bytes.into(), v).unwrap();

    // Check if this is a valid signature
    let tx = tx.clone().into_signed(signature);
    if tx.recover_signer().is_ok() {
      return tx;
    }

    // Re-hash until valid
    r = hash_to_scalar(r_bytes);
    s = hash_to_scalar(s_bytes);
  }
}
