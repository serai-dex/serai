use std::collections::{HashSet, HashMap};

use thiserror::Error;

use ciphersuite::{Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;

use crate::ReadWrite;

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum TransactionError {
  /// This transaction was perceived as invalid against the current state.
  #[error("transaction temporally invalid")]
  Temporal,
  /// This transaction is definitively invalid.
  #[error("transaction definitively invalid")]
  Fatal,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransactionKind {
  /// This tranaction should be provided by every validator, solely ordered by the block producer.
  ///
  /// This transaction is only valid if a supermajority of validators provided it.
  Provided,

  /// An unsigned transaction, only able to be included by the block producer.
  Unsigned,

  /// A signed transaction.
  Signed {
    signer: <Ristretto as Ciphersuite>::G,
    nonce: u32,
    signature: SchnorrSignature<Ristretto>,
  },
}

pub trait Transaction: Send + Sync + Clone + Eq + ReadWrite {
  fn kind(&self) -> TransactionKind;
  fn hash(&self) -> [u8; 32];

  fn verify(&self) -> Result<(), TransactionError>;
}

pub(crate) fn verify_transaction<T: Transaction>(
  tx: &T,
  locally_provided: &mut HashSet<[u8; 32]>,
  next_nonces: &mut HashMap<<Ristretto as Ciphersuite>::G, u32>,
) -> Result<(), TransactionError> {
  match tx.kind() {
    TransactionKind::Provided => {
      if !locally_provided.remove(&tx.hash()) {
        Err(TransactionError::Temporal)?;
      }
    }
    TransactionKind::Unsigned => {}
    TransactionKind::Signed { signer, nonce, signature } => {
      if next_nonces.get(&signer).cloned().unwrap_or(0) != nonce {
        Err(TransactionError::Temporal)?;
      }
      next_nonces.insert(signer, nonce + 1);

      // TODO: Use Schnorr half-aggregation and a batch verification here
      let mut wide = [0; 64];
      wide[.. 32].copy_from_slice(&tx.hash());
      if !signature.verify(signer, <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(&wide))
      {
        Err(TransactionError::Fatal)?;
      }
    }
  }

  tx.verify()
}
