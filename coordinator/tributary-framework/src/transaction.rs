use core::fmt::Debug;
use alloc::boxed::Box;
use std::io;

use blake2::{
  digest::{CustomizedInit as _, Digest as _},
  Blake2b256, Blake2b512,
};

use ciphersuite::{WrappedGroup, GroupIo};
use dalek_ff_group::Ristretto;
use schnorr::SchnorrSignature;

use crate::{ReadWrite, Digestible};

/// An error from a transaction.
#[derive(Clone, Debug)]
pub enum TransactionError {
  /// The transaction exceeded the size limit.
  ExceededSizeLimit,
  /// The transaction's signer wasn't a validator or was slashed.
  InvalidSigner,
  /// The transaction's signature was invalid.
  InvalidSignature,
  /// The transaction itself was invalid, as per [`Transaction::verify`].
  InvalidTransaction,
}

/// The signature data for a `Signed` transaction.
#[derive(Clone, Debug)]
pub struct Signed {
  /// The transaction's signer.
  ///
  /// This MUST be the Ristretto public key of a validator who has not been slashed.
  pub signer: [u8; 32],
  /// The transaction's nonce.
  ///
  /// This transaction WILL NOT be included until all prior nonces, within this transaction's
  /// scope, have appeared on-chain.
  pub nonce: u64,
  /// The Ristretto Schnorr signature.
  pub signature: [u8; 64],
}

impl ReadWrite for Signed {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let signer = {
      let mut signer = [0; 32];
      reader.read_exact(&mut signer)?;
      signer
    };

    let nonce = {
      let mut nonce = [0; 8];
      reader.read_exact(&mut nonce)?;
      u64::from_le_bytes(nonce)
    };

    let signature = {
      let mut signature = [0; 64];
      reader.read_exact(&mut signature)?;
      signature
    };

    Ok(Self { signer, nonce, signature })
  }

  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Self { signer, nonce, signature } = self;
    writer.write_all(signer)?;
    writer.write_all(&nonce.to_le_bytes())?;
    writer.write_all(signature)
  }
}

impl Signed {
  /// Read a `Signed` value _without its numeric nonce_.
  ///
  /// This is beneficial for contexts where the numeric nonce can be inferred from the
  /// transaction's content, allowing optimizing the encoding and reducing malleability.
  ///
  /// This has an incompatible wire format with `<Signed as ReadWrite>::read` and requires `nonce`
  /// be specified as an argument.
  pub fn read_without_nonce(mut reader: impl io::Read, nonce: u64) -> io::Result<Self> {
    let signer = {
      let mut signer = [0; 32];
      reader.read_exact(&mut signer)?;
      signer
    };

    let signature = {
      let mut signature = [0; 64];
      reader.read_exact(&mut signature)?;
      signature
    };

    Ok(Signed { signer, nonce, signature })
  }

  /// Write a `Signed` value _without its numeric nonce_.
  ///
  /// This function is the complement to [`Signed::read_without_nonce`].
  ///
  /// This has an incompatible wire format with `<Signed as ReadWrite>::write` and omits `nonce`
  /// from the serialization.
  pub fn write_without_nonce(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Self { signer, nonce: _, signature } = self;
    writer.write_all(signer)?;
    writer.write_all(signature)
  }
}

/// The type of a transaction.
///
/// This defines the transaction's required semantics for inclusion.
#[derive(Clone, Debug)]
pub enum TransactionKind {
  /// This transaction should be locally provided by every validator, in an exact order.
  ///
  /// The contained static string names a scope to use. This allows two distinct provided
  /// transactions, without synchrony, to be ordered within distinct scopes without mandating
  /// ordering with each other at time of provision. They will still be ordered into a single
  /// linear view once included on the agreed-upon blockchain.
  ///
  /// The only malleability SHOULD be when this transaction appears on chain. The block producer
  /// will only include provided transactions once locally provided, and validators will only vote
  /// for blocks with provided transactions if they were as locally provided.
  ///
  /// If a supermajority of validators produce a commit for a block with a provided transaction
  /// which isn't locally held, or even if it conflicts with a locally held provided transaction,
  /// the block will still be added to the local chain. The application MUST check the on-chain
  /// provided transactions are consistent with the local view.
  ///
  /// In order to ensure provided transactions aren't inadvertently provided multiple times, all
  /// provided transactions MUST have a unique hash. This is solely enforced _by the mempool_,
  /// where the literal blockchain solely requires a supermajority of validators agree on the
  /// ordering within a scope. Under an honest-supermajority assumption, the lack of provided
  /// transactions with identical hashes in local views (the mempools) will prevent such an
  /// occurrence on-chain.
  Provided {
    /// The scope for this provided transaction.
    scope: &'static str,
  },

  /// An unsigned transaction.
  ///
  /// This will be broadcast to other validators, who will add it to their mempool if they agree on
  /// the transaction's validity. No requirements on its ordering (in relation to any other
  /// transaction) are established.
  ///
  /// In order to ensure unsigned transactions aren't inadvertently included multiple times, all
  /// unsigned transactions MUST have a unique hash.
  Unsigned,

  /// A signed transaction.
  Signed {
    /// The scope for this signed transaction.
    ///
    /// The nonce within the [`Signed`] data is local to this scope.
    scope: Box<[u8]>,
    /// The [`Signed`] data associated with this.
    signed: Signed,
  },
}

/// A Tributary transaction.
///
/// The implementation of `Digestible` MUST be binding to the entire transaction _except_ its
/// signature (if signed).
pub trait Transaction: Clone + ReadWrite + Digestible {
  /// The size limit for a transaction.
  ///
  /// The Tributary will enforce no individual transaction exceeds this size.
  ///
  /// Transactions MUST be able to be included within a block's size limit.
  ///
  /// The default size limit is 2 MiB.
  const SIZE_LIMIT: Option<usize> = Some(2 * 1024 * 1024);

  /// The size limit for a block.
  ///
  /// The Tributary will enforce no individual block exceeds this size.
  ///
  /// This MUST be greater than the size of an empty block. This SHOULD be greater than the maximum
  /// size of a slash, else some slashes may be impossible to record on-chain.
  ///
  /// The default size limt is 5 MiB.
  const BLOCK_SIZE_LIMIT: Option<usize> = Some(5 * 1024 * 1024);

  /// The type of transaction this is.
  fn kind(&self) -> TransactionKind;

  /// Verify this transaction's content.
  ///
  /// This MUST be a context-free validation over the data within this transaction alone. This
  /// function is only required to apply application-specific verification rules, where the
  /// Tributary will always apply its rules and any rules regarding the current context.
  fn verify(&self) -> Result<(), TransactionError>;

  /// Obtain the challenge for this transaction's signature.
  ///
  /// This MUST return `Some(_)`  when `TransactionKind::Signed { .. }` and `None` otherwise.
  ///
  /// The provided implementation uses BLAKE2b-512, with a personalization of "tributary tx sig",
  /// for its hash function. It scopes to a specific Tributary via its genesis before digesting the
  /// transaction and the present signature's nonce (its first `32` bytes).
  fn signature_challenge(&self, genesis: [u8; 32]) -> Option<<Ristretto as WrappedGroup>::F> {
    let TransactionKind::Signed { scope: _, signed: Signed { signature, .. } } = self.kind() else {
      None?
    };
    Some(<Ristretto as WrappedGroup>::F::from_bytes_mod_order_wide(&{
      let genesis_scoped = Blake2b512::new_customized(b"tributary tx sig").chain_update(genesis);
      let tx_scoped = self.chain_update(genesis_scoped);
      let nonce_scoped = tx_scoped.chain_update(&signature[.. 32]);
      nonce_scoped.finalize().into()
    }))
  }

  /// Hash this transaction.
  ///
  /// The provided implementation uses BLAKE2b-256, with a personalization of "tributary tx", for
  /// its hash function. The implementation MUST be binding to the entire value's [`Digestible`]
  /// content.
  fn hash(&self) -> [u8; 32] {
    self.chain_update(Blake2b256::new_customized(b"tributary tx")).finalize().into()
  }
}

pub(crate) fn verify_syntax<T: Transaction>(
  tx: &T,
  genesis: [u8; 32],
) -> Result<(), TransactionError> {
  {
    let transaction_size_limit_by_block_size_limit = match T::BLOCK_SIZE_LIMIT
      .map(|block_size_limit| block_size_limit.checked_sub(crate::Block::<T>::EMPTY_BLOCK_SIZE))
    {
      Some(Some(transaction_size_limit_by_block_size_limit)) => {
        Some(transaction_size_limit_by_block_size_limit)
      }
      // The block size limit is less than the size of an empty block, so any block (and
      // therefore any transactions) will be syntactically invalid
      Some(None) => Err(TransactionError::ExceededSizeLimit)?,
      None => None,
    };
    let transaction_size =
      crate::serialized_len(tx).map_err(|_| TransactionError::ExceededSizeLimit)?;
    let exceeds_size_limit = |size_limit: Option<usize>| {
      size_limit.is_some_and(|size_limit| transaction_size > size_limit)
    };
    if exceeds_size_limit(T::SIZE_LIMIT) ||
      exceeds_size_limit(transaction_size_limit_by_block_size_limit)
    {
      Err(TransactionError::ExceededSizeLimit)?;
    }
  }

  if let Some(signature_challenge) = tx.signature_challenge(genesis) {
    let TransactionKind::Signed { scope: _, signed: Signed { signer, nonce: _, signature } } =
      tx.kind()
    else {
      panic!(
        "`Transaction::signature_challenge` returned `Some(_)` when not `TransactionKind::Signed`"
      );
    };
    let signer = <Ristretto as GroupIo>::read_G(&mut signer.as_slice())
      .map_err(|_| TransactionError::InvalidSigner)?;
    let signature = SchnorrSignature::<Ristretto>::read(&mut signature.as_slice())
      .map_err(|_| TransactionError::InvalidSignature)?;
    // TODO: Queue this for batch verification
    if !signature.verify(signer, signature_challenge) {
      Err(TransactionError::InvalidSignature)?;
    }
  }

  tx.verify()?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(Clone)]
  pub(crate) struct TestTransaction {
    pub(crate) valid: bool,
    pub(crate) kind: TransactionKind,
    pub(crate) salt: u8,
  }

  impl ReadWrite for TestTransaction {
    fn read(mut reader: impl io::Read) -> io::Result<Self> {
      let mut valid = [0xff; 1];
      reader.read_exact(&mut valid)?;
      let valid = valid[0] == 1;

      let mut kind = [0xff];
      reader.read_exact(&mut kind)?;
      let kind = match kind[0] {
        0xff => TransactionKind::Provided { scope: "provided 0" },
        0xfe => TransactionKind::Provided { scope: "provided 1" },
        1 => TransactionKind::Unsigned,
        2 => TransactionKind::Signed {
          scope: {
            let mut scope = [0];
            reader.read_exact(&mut scope)?;
            let mut scope = alloc::vec![0; usize::from(scope[0])].into_boxed_slice();
            reader.read_exact(&mut scope)?;
            scope
          },
          signed: Signed::read(&mut reader)?,
        },
        _ => Err(io::Error::other("unrecognized transaction kind"))?,
      };

      let mut salt = [0xff];
      reader.read_exact(&mut salt)?;
      let salt = salt[0];

      Ok(Self { valid, kind, salt })
    }

    fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
      writer.write_all(&[u8::from(self.valid)])?;
      match &self.kind {
        TransactionKind::Provided { scope } => {
          writer.write_all(&[match *scope {
            "provided 0" => 0xff,
            "provided 1" => 0xfe,
            _ => panic!("unexpected scope"),
          }])?;
        }
        TransactionKind::Unsigned => {
          writer.write_all(&[1])?;
        }
        TransactionKind::Signed { scope, signed } => {
          writer.write_all(&[2])?;
          writer.write_all(&[u8::try_from(scope.len()).unwrap()])?;
          writer.write_all(scope)?;
          signed.write(&mut writer)?;
        }
      }
      writer.write_all(&[self.salt])?;

      Ok(())
    }
  }

  impl crate::merkle::Digestible for TestTransaction {
    fn update(&self, digest: &mut (impl ?Sized + blake2::digest::Update)) {
      let serialization = self.serialize();
      let mut serialization = serialization.as_slice();
      if matches!(&self.kind, TransactionKind::Signed { .. }) {
        serialization = &serialization[.. (serialization.len() - 64)];
      }
      digest.update(serialization);
    }
  }

  impl Transaction for TestTransaction {
    fn kind(&self) -> TransactionKind {
      self.kind.clone()
    }
    fn verify(&self) -> Result<(), TransactionError> {
      self.valid.ok_or(TransactionError::InvalidTransaction)
    }
  }
}
#[cfg(test)]
pub(crate) use tests::TestTransaction;
