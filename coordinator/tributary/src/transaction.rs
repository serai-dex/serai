use core::fmt::Debug;
use std::{io, collections::HashMap};

use zeroize::Zeroize;
use thiserror::Error;

use blake2::{Digest, Blake2b512};

use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::{TRANSACTION_SIZE_LIMIT, ReadWrite};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum TransactionError {
  /// Transaction exceeded the size limit.
  #[error("transaction is too large")]
  TooLargeTransaction,
  /// Transaction's signer isn't a participant.
  #[error("invalid signer")]
  InvalidSigner,
  /// Transaction's nonce isn't the prior nonce plus one.
  #[error("invalid nonce")]
  InvalidNonce,
  /// Transaction's signature is invalid.
  #[error("invalid signature")]
  InvalidSignature,
  /// Transaction's content is invalid.
  #[error("transaction content is invalid")]
  InvalidContent,
}

/// Data for a signed transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signed {
  pub signer: <Ristretto as Ciphersuite>::G,
  pub nonce: u32,
  pub signature: SchnorrSignature<Ristretto>,
}

impl ReadWrite for Signed {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let signer = Ristretto::read_G(reader)?;

    let mut nonce = [0; 4];
    reader.read_exact(&mut nonce)?;
    let nonce = u32::from_le_bytes(nonce);
    if nonce >= (u32::MAX - 1) {
      Err(io::Error::new(io::ErrorKind::Other, "nonce exceeded limit"))?;
    }

    let mut signature = SchnorrSignature::<Ristretto>::read(reader)?;
    if signature.R.is_identity().into() {
      // Anyone malicious could remove this and try to find zero signatures
      // We should never produce zero signatures though meaning this should never come up
      // If it does somehow come up, this is a decent courtesy
      signature.zeroize();
      Err(io::Error::new(io::ErrorKind::Other, "signature nonce was identity"))?;
    }

    Ok(Signed { signer, nonce, signature })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    // This is either an invalid signature or a private key leak
    if self.signature.R.is_identity().into() {
      Err(io::Error::new(io::ErrorKind::Other, "signature nonce was identity"))?;
    }
    writer.write_all(&self.signer.to_bytes())?;
    writer.write_all(&self.nonce.to_le_bytes())?;
    self.signature.write(writer)
  }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransactionKind<'a> {
  /// This transaction should be provided by every validator, in an exact order.
  ///
  /// The contained static string names the orderer to use. This allows two distinct provided
  /// transaction kinds, without a synchronized order, to be ordered within their own kind without
  /// requiring ordering with each other.
  ///
  /// The only malleability is in when this transaction appears on chain. The block producer will
  /// include it when they have it. Block verification will fail for validators without it.
  ///
  /// If a supermajority of validators produce a commit for a block with a provided transaction
  /// which isn't locally held, the block will be added to the local chain. When the transaction is
  /// locally provided, it will be compared for correctness to the on-chain version
  Provided(&'static str),

  /// An unsigned transaction, only able to be included by the block producer.
  ///
  /// Once an Unsigned transaction is included on-chain, it may not be included again. In order to
  /// have multiple Unsigned transactions with the same values included on-chain, some distinct
  /// nonce must be included in order to cause a distinct hash.
  Unsigned,

  /// A signed transaction.
  Signed(&'a Signed),
}

// TODO: Should this be renamed TransactionTrait now that a literal Transaction exists?
// Or should the literal Transaction be renamed to Event?
pub trait Transaction: 'static + Send + Sync + Clone + Eq + Debug + ReadWrite {
  /// Return what type of transaction this is.
  fn kind(&self) -> TransactionKind<'_>;

  /// Return the hash of this transaction.
  ///
  /// The hash must NOT commit to the signature.
  fn hash(&self) -> [u8; 32];

  /// Perform transaction-specific verification.
  fn verify(&self) -> Result<(), TransactionError>;

  /// Obtain the challenge for this transaction's signature.
  ///
  /// Do not override this unless you know what you're doing.
  ///
  /// Panics if called on non-signed transactions.
  fn sig_hash(&self, genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    match self.kind() {
      TransactionKind::Signed(Signed { signature, .. }) => {
        <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(
          &Blake2b512::digest(
            [
              b"Tributary Signed Transaction",
              genesis.as_ref(),
              &self.hash(),
              signature.R.to_bytes().as_ref(),
            ]
            .concat(),
          )
          .into(),
        )
      }
      _ => panic!("sig_hash called on non-signed transaction"),
    }
  }
}

// This will only cause mutations when the transaction is valid
pub(crate) fn verify_transaction<T: Transaction>(
  tx: &T,
  genesis: [u8; 32],
  next_nonces: &mut HashMap<<Ristretto as Ciphersuite>::G, u32>,
) -> Result<(), TransactionError> {
  if tx.serialize().len() > TRANSACTION_SIZE_LIMIT {
    Err(TransactionError::TooLargeTransaction)?;
  }

  tx.verify()?;

  match tx.kind() {
    TransactionKind::Provided(_) => {}
    TransactionKind::Unsigned => {}
    TransactionKind::Signed(Signed { signer, nonce, signature }) => {
      if let Some(next_nonce) = next_nonces.get(signer) {
        if nonce != next_nonce {
          Err(TransactionError::InvalidNonce)?;
        }
      } else {
        // Not a participant
        Err(TransactionError::InvalidSigner)?;
      }

      // TODO: Use Schnorr half-aggregation and a batch verification here
      if !signature.verify(*signer, tx.sig_hash(genesis)) {
        Err(TransactionError::InvalidSignature)?;
      }

      next_nonces.insert(*signer, nonce + 1);
    }
  }

  Ok(())
}
