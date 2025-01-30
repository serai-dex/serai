#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use ::borsh::{BorshSerialize, BorshDeserialize};

use group::ff::PrimeField;
use k256::Scalar;

use alloy_primitives::PrimitiveSignature;
use alloy_consensus::{SignableTransaction, Signed, TxLegacy};

mod borsh;
pub use borsh::*;

/// An index of a log within a block.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "::borsh")]
pub struct LogIndex {
  /// The hash of the block which produced this log.
  pub block_hash: [u8; 32],
  /// The index of this log within the execution of the block.
  pub index_within_block: u64,
}

/// The Keccak256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  alloy_primitives::keccak256(data.as_ref()).into()
}

/// Deterministically sign a transaction.
///
/// This signs a transaction via setting a signature of `r = 1, s = 1`. The purpose of this is to
/// be able to send a transaction from an account which no one knows the private key for and no
/// other messages may be signed for from.
///
/// This function panics if passed a transaction with a non-None chain ID. This is because the
/// signer for this transaction is only singular across any/all EVM instances if it isn't binding
/// to an instance.
pub fn deterministically_sign(tx: TxLegacy) -> Signed<TxLegacy> {
  assert!(
    tx.chain_id.is_none(),
    "chain ID was Some when deterministically signing a TX (causing a non-singular signer)"
  );

  /*
    ECDSA signatures are:
    - x = private key
    - k = rand()
    - R = k * G
    - r = R.x()
    - s = (H(m) + (r * x)) * k.invert()

    Key recovery is performed via:
    - a = s * R = (H(m) + (r * x)) * G
    - b = a - (H(m) * G) = (r * x) * G
    - X = b / r = x * G
    - X = ((s * R) - (H(m) * G)) * r.invert()

    This requires `r` be non-zero and `R` be recoverable from `r` and the parity byte. For
    `r = 1, s = 1`, this sets `X` to `R - (H(m) * G)`. Since there is an `R` recoverable for
    `r = 1`, since the `R` is a point with an unknown discrete logarithm w.r.t. the generator, and
    since the resulting key is dependent on the message signed for, this will always work to
    the specification.
  */

  let r = Scalar::ONE;
  let s = Scalar::ONE;
  let r_bytes: [u8; 32] = r.to_repr().into();
  let s_bytes: [u8; 32] = s.to_repr().into();
  let signature =
    PrimitiveSignature::from_scalars_and_parity(r_bytes.into(), s_bytes.into(), false);

  let res = tx.into_signed(signature);
  debug_assert!(res.recover_signer().is_ok());
  res
}

#[test]
fn test_deterministically_sign() {
  let tx = TxLegacy { chain_id: None, ..Default::default() };
  let signed = deterministically_sign(tx.clone());

  assert!(signed.recover_signer().is_ok());
  let one = alloy_primitives::U256::from(1u64);
  assert_eq!(signed.signature().r(), one);
  assert_eq!(signed.signature().s(), one);

  let mut other_tx = tx.clone();
  other_tx.nonce += 1;
  // Signing a distinct message should yield a distinct signer
  assert!(
    signed.recover_signer().unwrap() != deterministically_sign(other_tx).recover_signer().unwrap()
  );
}
