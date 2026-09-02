use core::time::Duration;
use alloc::{boxed::Box, vec::Vec};
use std::{io, time::SystemTime};

use blake2::{digest::Digest as _, Blake2b256};

use crate::{
  ReadWrite, Slash,
  transaction::{TransactionError, Signed, TransactionKind, Transaction},
};

/// An error with regards to a block's validity.
#[derive(Clone, Debug)]
pub enum SyntacticError {
  /// The block exceeded the size limit.
  ExceededSizeLimit,
  /// The block's header specified Merkle tree roots for distinct contents.
  IncorrectContents,
  /// The block's timestamp was absurd.
  AbsurdTime,
  /// The block's contents weren't ordered as expected.
  ///
  /// The presence of conflicting contents will be considered an invalid ordering.
  IncorrectOrderOfContents,
  /// An invalid transaction was included.
  Transaction(TransactionError),
}

impl From<TransactionError> for SyntacticError {
  fn from(error: TransactionError) -> SyntacticError {
    SyntacticError::Transaction(error)
  }
}

/// An error with regards to a block's validity once contextualized by the blockchain.
#[derive(Clone, Debug)]
pub enum SemanticError {
  /// The block's time is too close to the prior block's.
  TooSoon,
  /// A slash had an invalid reason.
  InvalidSlash {
    /// The validator the slash was for.
    validator: [u8; 32],
  },
  /// An included slash slashes a validator who has already been slashed.
  SlashAlreadyIncluded {
    /// The validator the slash was for.
    validator: [u8; 32],
  },
  /// The provided transaction was distinct from the locally provided transaction.
  DistinctProvided {
    /// The provided transactions' scope.
    scope: &'static str,
    /// The hash of the provided transaction included in this block.
    transaction_hash: [u8; 32],
    /// The hash of the expected provided transaction.
    expected_hash: [u8; 32],
  },
  /// An unsigned transaction included in this block was already included on the blockchain.
  UnsignedAlreadyIncluded {
    /// The hash of the unsigned transaction which was already included.
    transaction_hash: [u8; 32],
  },
  /// The signer of this transaction was slashed.
  ///
  /// This means the signer was not a validator who has yet to be slashed.
  InvalidSigner {
    /// The invalid signer who signed a transaction included in this block.
    signer: [u8; 32],
  },
  /// There is a gap between a transaction included in this block and the last relevant transaction
  /// included on-chain.
  Gap {
    /// The hash of the transaction included in this block.
    transaction_hash: [u8; 32],
    /// The nonce of the transaction included in this block.
    transaction_nonce: u64,
    /// The expected nonce for the next transaction within the same scope.
    expected_nonce: u64,
  },
}

/// An error with regards to a block's validity _per the local view_.
#[derive(Clone, Debug)]
pub enum EphemeralError {
  /// The block's header specified a parent which wasn't the chain tip.
  UnexpectedParent,
  /// This block occurs in the future.
  Future,
  /// The block had a provided transaction this validator has yet to provide.
  NotLocallyProvidedTransaction {
    /// The provided transaction's scope.
    scope: &'static str,
    /// The hash of the provided transaction included in this block.
    transaction_hash: [u8; 32],
  },
}

/// An error with a block.
#[derive(Clone, Debug)]
pub enum BlockError {
  /// An error with regards to a block's validity.
  Syntactic(SyntacticError),
  /// An error with regards to a block's validity once contextualized by the blockchain.
  Semantic(SemanticError),
  /// An error with regards to a block's validity _per the local view_.
  Ephemeral(EphemeralError),
}

impl From<SyntacticError> for BlockError {
  fn from(error: SyntacticError) -> BlockError {
    BlockError::Syntactic(error)
  }
}

impl From<TransactionError> for BlockError {
  fn from(error: TransactionError) -> BlockError {
    BlockError::from(SyntacticError::from(error))
  }
}

impl From<SemanticError> for BlockError {
  fn from(error: SemanticError) -> BlockError {
    BlockError::Semantic(error)
  }
}

impl From<EphemeralError> for BlockError {
  fn from(error: EphemeralError) -> BlockError {
    BlockError::Ephemeral(error)
  }
}

/// The header for a block.
///
/// This is binding to the block's ancestry and contents. It allows creating a view of every block
/// on the blockchain, without syncing each individual block. Combined with a consensus commitment
/// for the most recent block on the blockchain, this can certify agreement over an entire
/// blockchain without syncing any transactions.
///
/// This is a fixed-size container. It is defined as the 104-byte concatenation of:
/// - the block's parent's hash
/// - the little-endian encoding of the eight-byte quantity of milliseconds since the epoch
/// - the Merkle tree root for the slashes within this block
/// - the Merkle tree root for the transactions within this block
///
/// Including the block's time in the header is an unfortunate byproduct of implementing a minimum
/// spacing between blocks. Such a spacing effectively requires knowing when a block was proposed,
/// to know when the next block should be proposed.
///
/// Commitments from consensus, as needed to certify agreement on this block, are intentionally
/// left separate. Consensus commitments are not canonical and any unnecessary or redundant
/// commitments MAY be pruned.
/*
  TODO: Should this include the block's _number_? Then we could distinguish between
  `UnexpectedParent` as an ephemeral error with the local view and as a semantic error.
*/
/*
  TODO: Should we define the parent hash as a Merkle tree, not a line of hashes? This would enable
  optimizing the sync protocol by requesting different chunks from different validators. We just
  have to deal with the complexity of so defining it. While the Serai libraries do define a
  incremental Merkle tree, if we do not wish to directly depend on those libraries, we'd have to
  write one when the data structure only really makes sense when backed by the underlying database.

  That isn't unacceptable, it just questions the functionality vs. the complexity of the
  Tributary SDK.
*/
#[derive(Clone, Copy, Debug)]
pub struct BlockHeader {
  parent: [u8; 32],
  time: u64,
  slashes: [u8; 32],
  transactions: [u8; 32],
}

impl ReadWrite for BlockHeader {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let parent = {
      let mut parent = [0; 32];
      reader.read_exact(&mut parent)?;
      parent
    };
    let time = {
      let mut time = [0; 8];
      reader.read_exact(&mut time)?;
      u64::from_le_bytes(time)
    };
    let slashes = {
      let mut slashes = [0; 32];
      reader.read_exact(&mut slashes)?;
      slashes
    };
    let transactions = {
      let mut transactions = [0; 32];
      reader.read_exact(&mut transactions)?;
      transactions
    };
    Ok(Self { parent, time, slashes, transactions })
  }

  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Self { parent, time, slashes, transactions } = self;
    writer.write_all(parent)?;
    writer.write_all(&time.to_le_bytes())?;
    writer.write_all(slashes)?;
    writer.write_all(transactions)
  }
}

impl crate::merkle::Digestible for BlockHeader {
  fn update(&self, digest: &mut (impl ?Sized + blake2::digest::Update)) {
    self.write(crate::merkle::DigestWriter(digest)).expect("`DigestWriter` is infallible");
  }
}

impl BlockHeader {
  const SIZE: usize = 32 + 8 + 32 + 32;

  /// The slashes this block header commits to.
  pub fn slashes(&self) -> [u8; 32] {
    self.slashes
  }

  /// The time embedded within this block header.
  ///
  /// This is represented in milliseconds since the epoch.
  pub fn time(&self) -> u64 {
    self.time
  }

  /// The transactions this block commits to.
  pub fn transactions(&self) -> [u8; 32] {
    self.transactions
  }

  /// The hash for this block header.
  ///
  /// The hash is the BLAKE2b-256 hash (without any personalization) of the block header's
  /// serialization.
  pub fn hash(&self) -> [u8; 32] {
    crate::merkle::Digestible::chain_update(self, Blake2b256::new()).finalize().into()
  }
}

/// A block.
///
/// A block is defined as its header, a list of slashes, amd a list of transactions, as committed
/// to within the block's header.
///
/// The slashes MUST be sorted by the slashed validator.
///
/// The transactions MUST be ordered as provided, unsigned, signed, with:
/// - The provided transactions sorted by their scopes
/// - The unsigned transactions sorted by their hashes
/// - The signed transactions sorted by their signers, then their scopes, then their nonces
///
/// These strict requirements on ordering allow single-pass verification, without any dynamic
/// allocations, that a block is free of conflicting unsigned/signed transactions (a problem which
/// is considered an instance of an invalid ordering). It also allows checking provided
/// transactions one scope at a time, and straight-line application of a block's signed
/// transactions, after having prioritized the provided and unsigned transactions which imply some
/// level of recognition within the application.
///
/// The Tributary DOES NOT enforce the uniqueness of signed transactions' hashes, where signed
/// transactions' hashes MUST bind to all of their semantic contents.
///
/// The block's serialization prefixes the list of slashes with the two-byte little-endian encoding
/// of its length and the list of transactions with the four-byte little-endian encoding of its
/// length. The limit on slashes is complete as there are at most [`u16::MAX`] validators. The
/// limit on transactions is practical and enforced as a syntactic requirement.
#[derive(Clone, Debug)]
pub struct Block<T: Transaction> {
  header: BlockHeader,
  slashes: Box<[Slash]>,
  transactions: Box<[T]>,
}

impl<T: Transaction> ReadWrite for Block<T> {
  /// This will read a block with no size limits applied. While this will not reserve capacity for
  /// the _alleged_ length of lists, meaning the amount of memory consumed is proportional to the
  /// amount of bytes read, the caller is expected to ensure they are prepared to read this block
  /// in its entirety.
  ///
  /// Applications SHOULD apply their own size limit to the reader itself to prevent a potential
  /// Denial of Service by transmitting several GB of data which, if deserialized, will then be
  /// stored in memory.
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let header = BlockHeader::read(&mut reader)?;

    let slashes = (0 .. {
      let mut slashes = [0; 2];
      reader.read_exact(&mut slashes)?;
      u16::from_le_bytes(slashes)
    })
      .map(|_| Slash::read(&mut reader))
      .collect::<Result<Vec<_>, _>>()?
      .into_boxed_slice();

    let transactions = (0 .. {
      let mut transactions = [0; 4];
      reader.read_exact(&mut transactions)?;
      u32::from_le_bytes(transactions)
    })
      .map(|_| T::read(&mut reader))
      .collect::<Result<Vec<_>, _>>()?
      .into_boxed_slice();

    Ok(Block { header, slashes, transactions })
  }

  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Block { header, slashes, transactions } = self;
    header.write(&mut writer)?;

    writer.write_all(
      &u16::try_from(slashes.len())
        .map_err(|_| io::Error::other("block has more slashes than validators"))?
        .to_le_bytes(),
    )?;
    for slash in slashes {
      slash.write(&mut writer)?;
    }

    writer.write_all(
      &u32::try_from(transactions.len())
        .map_err(|_| io::Error::other("block has more than four billion transactions"))?
        .to_le_bytes(),
    )?;
    for tx in transactions {
      tx.write(&mut writer)?;
    }

    Ok(())
  }
}

impl<T: Transaction> Block<T> {
  /// The serialized length of an empty block.
  ///
  /// This is equal to the serialized length of a block header, followed by the lengths of the
  /// (empty) list of slashes and the (empty) list of transactions.
  pub(crate) const EMPTY_BLOCK_SIZE: usize = BlockHeader::SIZE + 2 + 4;

  /// This block's time, represented as a `SystemTime`.
  pub(crate) fn system_time(&self) -> Result<SystemTime, SyntacticError> {
    let Some(time) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(self.time())) else {
      // This block's time is absurd
      Err(SyntacticError::AbsurdTime)?
    };
    Ok(time)
  }

  /// Verify this block's syntax.
  ///
  /// This is a check which can be performed without any context or state, other than the genesis
  /// hash, allowing it to be performed in response to network traffic _before_ acquiring any
  /// mutexes or occupying any channels.
  ///
  /// This DOES verify the slashed validators are committed to within the block's header. This
  /// DOES NOT verify the slashes themselves, which is semantic. This enables malleability in that
  /// a malicious peer MAY substitute a valid slash reason for a validator with an invalid slash
  /// reason for the same validator. The reason for a slash may be verified via [`Slash::verify`],
  /// solely requiring the context which spawned the Tributary (not its current state).
  ///
  /// This DOES verify the transactions are committed to within the block's header. This DOES
  /// verify the signed transaction's signatures. If the application's transaction type omits
  /// signatures from the transaction's hash, due to them not affecting the semantic meaning of the
  /// transaction, a malicious peer MAY substitute a signed transaction's valid signature with an
  /// invalid signature.
  ///
  /// If the block is agreed upon by the validators via the consensus process, there MUST be valid
  /// uncommitted data available _so long as the honest-majority assumption is upheld_. This means
  /// if a block is received with invalid data _which wasn't committed to_, but the block is agreed
  /// upon, it is the _peer_ which should be considered valid, not the block. The uncommitted data
  /// should be retrieved from an honest peer instead.
  ///
  /// For blocks _without agreement under consensus_, it would not appear immediate to determine if
  /// a block with invalid uncommitted data is due to a malicious proposer or a malicious peer.
  /// However, if the block was received from a peer who isn't the proposer, the peer MUST be
  /// faulty, as the peer either malleated the block to be invalid themselves _or_ chose to relay
  /// an invalid block (assuming the gossip layer does not simply relay every message seen without
  /// any scrutiny).
  pub fn verify_syntax(&self, genesis: [u8; 32]) -> Result<(), SyntacticError> {
    // This length is serialized as a `u32`, so it must be less than or equal to `u32::MAX`
    if self.transactions.len() >
      const {
        #[expect(clippy::eq_op, clippy::manual_assert)]
        if 4_294_967_295 != u32::MAX {
          panic!("inlined `u32::MAX` constant wasn't correct");
        }
        4_294_967_295
      }
    {
      Err(SyntacticError::ExceededSizeLimit)?;
    }

    // Check this block's encoded length is less than the block size limit
    if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT &&
      (crate::serialized_len(self).map_err(|_| SyntacticError::ExceededSizeLimit)? >
        block_size_limit)
    {
      Err(SyntacticError::ExceededSizeLimit)?;
    }

    if (self.header.slashes != crate::merkle::root::<Slash>(self.slashes.iter())) ||
      (self.header.transactions != crate::merkle::root::<T>(self.transactions.iter()))
    {
      Err(SyntacticError::IncorrectContents)?;
    }

    self.system_time()?;

    // Ensure the slashes are sorted
    {
      let mut last_validator = None;
      for slash in &self.slashes {
        if Some(slash.validator()) <= last_validator {
          Err(SyntacticError::IncorrectOrderOfContents)?;
        }
        last_validator = Some(slash.validator());
      }
    }

    {
      let mut kind = 0;
      let mut last_hash_or_validator = None;
      let mut last_nonce = None;
      let mut last_signed_scope = None;
      let mut last_provided_scope = None;
      for transaction in &self.transactions {
        {
          // Ensure this is sorted as provided, unsigned, signed
          let transaction_kind = match transaction.kind() {
            TransactionKind::Provided { .. } => 0,
            TransactionKind::Unsigned => 1,
            TransactionKind::Signed { .. } => 2,
          };
          if transaction_kind < kind {
            Err(SyntacticError::IncorrectOrderOfContents)?;
          }

          // If we are switching kinds, reset our trackers for the last values
          if transaction_kind > kind {
            last_hash_or_validator = None;
            last_nonce = None;
            last_signed_scope = None;
            last_provided_scope = None;
            kind = transaction_kind;
          }
        }

        match transaction.kind() {
          TransactionKind::Provided { scope } => {
            if Some(scope.as_bytes()) < last_provided_scope.map(str::as_bytes) {
              Err(SyntacticError::IncorrectOrderOfContents)?;
            }
            last_provided_scope = Some(scope);
          }
          TransactionKind::Unsigned => {
            let hash = transaction.hash();
            // `<` is for incorrect order
            // `=` is for multiple inclusions, reported here as an incorrect order
            if Some(hash) <= last_hash_or_validator {
              Err(SyntacticError::IncorrectOrderOfContents)?;
            }
            last_hash_or_validator = Some(hash);
          }
          TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
            // Ensure ordering by signer
            if Some(signer) < last_hash_or_validator {
              Err(SyntacticError::IncorrectOrderOfContents)?;
            }
            // If we're onto the next signer's transactions, reset the scope's tracker
            if Some(signer) > last_hash_or_validator {
              last_signed_scope = None;
              last_nonce = None;
              last_hash_or_validator = Some(signer);
            }

            // Ensure ordering by scope
            if Some(&scope) < last_signed_scope.as_ref() {
              Err(SyntacticError::IncorrectOrderOfContents)?;
            }
            // If we're onto a new scope, reset the tracker for the nonce
            if Some(&scope) > last_signed_scope.as_ref() {
              last_nonce = None;
              last_signed_scope = Some(scope);
            }

            // Ensure ordering by nonce
            if let Some(last_nonce) = last_nonce &&
              (nonce != (last_nonce + 1))
            {
              Err(SyntacticError::IncorrectOrderOfContents)?;
            }
            last_nonce = Some(nonce);
          }
        }

        crate::transaction::verify_syntax(transaction, genesis)?;
      }
    }

    Ok(())
  }

  /// Instantiate a block.
  ///
  /// This will check the block is syntactically valid via [`Block::verify_syntax`]. It is intended
  /// to enable optimized peer-to-peer layers, where the application syncs block headers
  /// independently from their contents, where fine control over each individual item is required
  /// (e.g. if a single item was malleated and should be replaced).
  pub fn instantiate(
    genesis: [u8; 32],
    parent: [u8; 32],
    time: u64,
    slashes: Box<[Slash]>,
    transactions: Box<[T]>,
  ) -> Result<Self, SyntacticError> {
    let result = Block {
      header: BlockHeader {
        parent,
        time,
        slashes: crate::merkle::root::<Slash>(slashes.iter()),
        transactions: crate::merkle::root::<T>(transactions.iter()),
      },
      slashes,
      transactions,
    };
    result.verify_syntax(genesis)?;
    Ok(result)
  }

  /// This block's parent's hash.
  pub fn parent(&self) -> [u8; 32] {
    self.header.parent
  }

  /// This block's time.
  ///
  /// See [`BlockHeader::time`] for more information.
  pub fn time(&self) -> u64 {
    self.header.time
  }

  /// The hash of this block.
  ///
  /// This is defined as the hash of its header.
  pub fn hash(&self) -> [u8; 32] {
    self.header.hash()
  }

  /// The slashes within this block.
  pub fn slashes(&self) -> &[Slash] {
    &self.slashes
  }

  /// The transactions within this block.
  pub fn transactions(&self) -> &[T] {
    &self.transactions
  }
}
