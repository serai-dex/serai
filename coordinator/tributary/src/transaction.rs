use core::fmt::Debug;
use std::{
  io,
  collections::{HashSet, HashMap},
};

use thiserror::Error;

use blake2::{Digest, Blake2b512};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;

use crate::ReadWrite;

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum TransactionError {
  /// A provided transaction wasn't locally provided.
  #[error("provided transaction wasn't locally provided")]
  MissingProvided([u8; 32]),
  /// This transaction's signer isn't a participant.
  #[error("invalid signer")]
  InvalidSigner,
  /// This transaction's nonce isn't the prior nonce plus one.
  #[error("invalid nonce")]
  InvalidNonce,
  /// This transaction's signature is invalid.
  #[error("invalid signature")]
  InvalidSignature,
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

    let signature = SchnorrSignature::<Ristretto>::read(reader)?;

    Ok(Signed { signer, nonce, signature })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.signer.to_bytes())?;
    writer.write_all(&self.nonce.to_le_bytes())?;
    self.signature.write(writer)
  }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransactionKind<'a> {
  /// This tranaction should be provided by every validator, solely ordered by the block producer.
  Provided,

  /// An unsigned transaction, only able to be included by the block producer.
  Unsigned,

  /// A signed transaction.
  Signed(&'a Signed),
}

pub trait Transaction: Send + Sync + Clone + Eq + Debug + ReadWrite {
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
  fn sig_hash(&self, genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(
      &Blake2b512::digest([genesis, self.hash()].concat()).into(),
    )
  }
}

// This will only cause mutations when the transaction is valid
pub(crate) fn verify_transaction<T: Transaction>(
  tx: &T,
  genesis: [u8; 32],
  locally_provided: &mut HashSet<[u8; 32]>,
  next_nonces: &mut HashMap<<Ristretto as Ciphersuite>::G, u32>,
) -> Result<(), TransactionError> {
  tx.verify()?;

  match tx.kind() {
    TransactionKind::Provided => {
      let hash = tx.hash();
      if !locally_provided.remove(&hash) {
        Err(TransactionError::MissingProvided(hash))?;
      }
    }
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
