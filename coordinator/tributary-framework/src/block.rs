use core::time::Duration;
use alloc::boxed::Box;
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
  ExceededSizeLimit {
    /// The size of the block when serialized.
    ///
    /// This may be `None` if this value couldn't be or wasn't calculated.
    size: Option<usize>,
  },
  /// The block's header specified Merkle tree roots for distinct contents.
  IncorrectContents,
  /// The block's timestamp was absurd.
  ///
  /// This is determined with respect to the system's representation of time ([`SystemTime`]).
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
  /// The signer of this transaction was invalid within the blockchain's context.
  ///
  /// The signer either was not a validator of the Tributary _or_ was a validator who had a slash
  /// included on-chain.
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
    ///
    /// This will be `None` on overflow.
    expected_nonce: Option<u64>,
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
  Tributary Framework.
*/
#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
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

  /// The parent this builds upon.
  ///
  /// This will be the genesis if this is the first block on the blockchain.
  pub fn parent(&self) -> [u8; 32] {
    self.parent
  }

  /// The time embedded within this block header.
  ///
  /// This is represented in milliseconds since the epoch.
  pub fn time(&self) -> u64 {
    self.time
  }

  /// The slashes this block header commits to.
  pub fn slashes(&self) -> [u8; 32] {
    self.slashes
  }

  /// The transactions this block header commits to.
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
      .collect::<Result<Box<[_]>, _>>()?;

    let transactions = (0 .. {
      let mut transactions = [0; 4];
      reader.read_exact(&mut transactions)?;
      u32::from_le_bytes(transactions)
    })
      .map(|_| T::read(&mut reader))
      .collect::<Result<Box<[_]>, _>>()?;

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

  fn verify_syntax_slashes<'block>(
    slashes: impl IntoIterator<Item = &'block Slash>,
  ) -> Result<(), SyntacticError> {
    slashes
      .into_iter()
      .is_sorted_by(|a, b| a.validator() < b.validator())
      .ok_or(SyntacticError::IncorrectOrderOfContents)
  }

  fn verify_syntax_transactions<'block>(
    genesis: [u8; 32],
    transactions: impl IntoIterator<Item = &'block T>,
  ) -> Result<(), SyntacticError>
  where
    T: 'block,
  {
    /*
      We check the ordering by checking the following tuple is greater with each iteration of the
      loop. This takes advantage of how `(T1, Tn, ...)` implements `PartialOrd` by comparing the
      first element, and only on equality, comparing the next element (until the tuple is
      exhausted).
    */
    #[expect(clippy::type_complexity)]
    let mut order: (
      u8,
      Option<&'static [u8]>,
      Option<[u8; 32]>,
      Option<([u8; 32], Box<[u8]>, u64)>,
    ) = (0, None, None, None);

    for transaction in transactions {
      let new_order = match transaction.kind() {
        TransactionKind::Provided { scope } => (0, Some(scope.as_bytes()), None, None),
        TransactionKind::Unsigned => (1, None, Some(transaction.hash()), None),
        TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
          /*
            If the last transaction was by this signer, within this scope, check this pair of
            transactions is contiguous and there's no gap between them.
          */
          if let Some((prior_signer, ref prior_scope, prior_nonce)) = order.3 &&
            (prior_signer == signer) &&
            (prior_scope == &scope) &&
            (prior_nonce.checked_add(1) != Some(nonce))
          {
            Err(SyntacticError::IncorrectOrderOfContents)?;
          }

          (2, None, None, Some((signer, scope, nonce)))
        }
      };

      // If this is a provided transaction...
      if order.0 == 0 {
        // Require scopes be sequential, but allow multiple transactions within a scope
        // (which all have the same order from a syntactic perspective)
        if new_order < order {
          Err(SyntacticError::IncorrectOrderOfContents)?;
        }
      } else if new_order <= order {
        // If this isn't a provided transaction, require strictly increasing orders
        Err(SyntacticError::IncorrectOrderOfContents)?;
      }
      order = new_order;

      crate::transaction::verify_syntax(transaction, genesis)?;
    }

    Ok(())
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
      Err(SyntacticError::ExceededSizeLimit { size: None })?;
    }

    // Check this block's encoded length is less than the block size limit
    if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT {
      let Ok(serialized_len) = crate::serialized_len(self) else {
        Err(SyntacticError::ExceededSizeLimit { size: None })?
      };
      if serialized_len > block_size_limit {
        Err(SyntacticError::ExceededSizeLimit { size: Some(serialized_len) })?;
      }
    }

    if (self.header.slashes != crate::merkle::root::<Slash>(self.slashes.iter())) ||
      (self.header.transactions != crate::merkle::root::<T>(self.transactions.iter()))
    {
      Err(SyntacticError::IncorrectContents)?;
    }

    // Check the block's time is representable
    self.system_time()?;

    Self::verify_syntax_slashes(&self.slashes)?;
    Self::verify_syntax_transactions(genesis, &self.transactions)?;

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
    let block = Block {
      header: BlockHeader {
        parent,
        time,
        slashes: crate::merkle::root::<Slash>(slashes.iter()),
        transactions: crate::merkle::root::<T>(transactions.iter()),
      },
      slashes,
      transactions,
    };
    block.verify_syntax(genesis)?;
    Ok(block)
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

#[test]
fn sizes() {
  use crate::transaction::TestTransaction;

  let header = BlockHeader {
    parent: [0xaa; 32],
    time: u64::MAX,
    slashes: [0xbb; 32],
    transactions: [0xcc; 32],
  };
  assert_eq!(header, BlockHeader::read(&mut header.serialize().as_slice()).unwrap());
  assert_eq!(header.serialize().len(), BlockHeader::SIZE);
  assert_eq!(
    (Block::<TestTransaction> { header, slashes: Box::default(), transactions: Box::default() })
      .serialize()
      .len(),
    Block::<TestTransaction>::EMPTY_BLOCK_SIZE
  );
}

#[test]
fn slashes() {
  use crate::transaction::TestTransaction;

  let slash = |validator: [u8; 32]| {
    let mut slash = validator.to_vec();
    loop {
      if let Ok(slash) = Slash::read(&mut slash.as_slice()) {
        return slash;
      }
      /*
        Because this slash isn't verified and doesn't have to be valid, just to deserialize into a
        valid instance of the literal data types, we just pad with non-zero bytes until it's the
        correct length to deserialize.
      */
      slash.push(1);
      assert!(slash.len() < (32 * 1_024), "32 KiB slash still couldn't be deserialized");
    }
  };

  Block::<TestTransaction>::verify_syntax_slashes([&slash([0xaa; 32])]).expect("one slash");
  Block::<TestTransaction>::verify_syntax_slashes([&slash([0xaa; 32]), &slash([0xbb; 32])])
    .expect("sorted");
  Block::<TestTransaction>::verify_syntax_slashes([&slash([0xaa; 32]), &slash([0xaa; 32])])
    .expect_err("multiple inclusions");
  Block::<TestTransaction>::verify_syntax_slashes([&slash([0xbb; 32]), &slash([0xaa; 32])])
    .expect_err("not sorted");
}

#[test]
fn transactions() {
  use core::ops::Deref as _;

  use zeroize::Zeroizing;
  use rand::rngs::OsRng;

  use ciphersuite::{
    group::{ff::PrimeField as _, GroupEncoding as _},
    WrappedGroup,
  };
  use dalek_ff_group::Ristretto;

  use crate::transaction::TestTransaction;

  let genesis = [0xfe; 32];

  let (alice, bob) = {
    let alice = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng));
    let bob = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng));
    if (<Ristretto as WrappedGroup>::generator() * alice.deref()).to_bytes() <
      (<Ristretto as WrappedGroup>::generator() * bob.deref()).to_bytes()
    {
      (alice, bob)
    } else {
      (bob, alice)
    }
  };

  let transaction = |(mut kind, salt)| {
    let mut key = None;
    let nonce = <Ristretto as WrappedGroup>::F::random(&mut OsRng);
    if let TransactionKind::Signed { scope: _, signed: Signed { signer, nonce: _, signature } } =
      &mut kind
    {
      let key_value = if *signer == [0xaa; 32] {
        &alice
      } else if *signer == [0xbb; 32] {
        &bob
      } else {
        panic!()
      };
      *signer = (<Ristretto as WrappedGroup>::generator() * key_value.deref()).to_bytes();
      key = Some(key_value);

      signature[.. 32]
        .copy_from_slice((<Ristretto as WrappedGroup>::generator() * nonce).to_bytes().as_ref());
    }

    let mut transaction = TestTransaction { valid: true, kind, salt };

    if let Some(signature_challenge) = transaction.signature_challenge(genesis) {
      let TransactionKind::Signed { scope: _, signed: Signed { signer: _, nonce: _, signature } } =
        &mut transaction.kind
      else {
        panic!("signature challenge but not signed")
      };
      let s = nonce + (signature_challenge * key.unwrap().deref());
      signature[32 ..].copy_from_slice(s.to_repr().as_ref());
    }

    transaction
  };

  // Provided transactions solely have to be ordered by scope
  let provided = [
    (TransactionKind::Provided { scope: "provided 0" }, 1),
    (TransactionKind::Provided { scope: "provided 0" }, 0),
    (TransactionKind::Provided { scope: "provided 1" }, 0),
  ]
  .into_iter()
  .map(transaction)
  .collect::<alloc::vec::Vec<_>>();

  // Unsigned transactions are ordered by hash
  let unsigned = {
    let mut unsigned = [(TransactionKind::Unsigned, 0), (TransactionKind::Unsigned, 1)]
      .into_iter()
      .map(transaction)
      .collect::<alloc::vec::Vec<_>>();
    unsigned.sort_by_key(Transaction::hash);
    unsigned
  };

  // Signed transactions are sorted by signer, then scope, then nonce
  let signed = [
    (TransactionKind::Signed {
      scope: alloc::vec![1].into_boxed_slice(),
      signed: Signed { signer: [0xaa; 32], nonce: 0, signature: [0; 64] },
    }),
    (TransactionKind::Signed {
      scope: alloc::vec![1].into_boxed_slice(),
      signed: Signed { signer: [0xaa; 32], nonce: 1, signature: [0; 64] },
    }),
    (TransactionKind::Signed {
      scope: alloc::vec![1].into_boxed_slice(),
      signed: Signed { signer: [0xaa; 32], nonce: 2, signature: [0; 64] },
    }),
    (TransactionKind::Signed {
      scope: alloc::vec![2].into_boxed_slice(),
      signed: Signed { signer: [0xaa; 32], nonce: 0, signature: [0; 64] },
    }),
    (TransactionKind::Signed {
      scope: alloc::vec![3].into_boxed_slice(),
      signed: Signed { signer: [0xaa; 32], nonce: 5, signature: [0; 64] },
    }),
    (TransactionKind::Signed {
      scope: alloc::vec![0].into_boxed_slice(),
      signed: Signed { signer: [0xbb; 32], nonce: 0, signature: [0; 64] },
    }),
  ]
  .into_iter()
  .map(|kind| transaction((kind, 0)))
  .collect::<alloc::vec::Vec<_>>();

  {
    let transactions = provided.iter().chain(unsigned.iter()).chain(signed.iter());
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions).expect("sorted");
  }

  {
    let transactions = unsigned.iter().chain(provided.iter());
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("unsigned before provided");
  }

  {
    let transactions = signed.iter().chain(provided.iter());
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("signed before provided");
  }

  {
    let transactions = signed.iter().chain(unsigned.iter());
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("signed before unsigned");
  }

  {
    let transactions = provided.iter().rev();
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("provided with reversed scopes");
  }

  {
    let transactions = unsigned.iter().rev();
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("unsigned with reversed hashes");
  }

  {
    let transactions = unsigned.first().into_iter().chain(unsigned.iter());
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("unsigned with repeated transactions");
  }

  /*
    Try every permutation of signed transactions, as they should only have a singular valid
    ordering (the one they were defined in).

    This generates every ordering via incrementing a
    multi-digit value (the set of indexes, each digit one index),
    exhausting its space of representable values. When the multi-digit value overflows, we're done.
  */
  {
    fn increment(digits: &mut [usize], limit: usize) -> bool {
      let mut carry = true;
      for digit in digits {
        *digit += usize::from(u8::from(carry));
        carry = *digit == limit;
        if carry {
          *digit = 0;
        }
      }
      !carry
    }
    let mut order = alloc::vec![0; signed.len()];
    while increment(&mut order, signed.len()) {
      if order != (0 .. signed.len()).collect::<alloc::vec::Vec<_>>() {
        let transactions = order.iter().map(|i| &signed[*i]);
        Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
          .expect_err("non-sorted signed transactions");
      }
    }
  }

  {
    let transactions =
      signed.iter().filter(|transaction| {
        if let TransactionKind::Signed {
          scope: _,
          signed: Signed { signer: _, nonce, signature: _ },
        } = transaction.kind() &&
          (nonce == 1)
        {
          return false;
        }
        true
      });
    Block::<TestTransaction>::verify_syntax_transactions(genesis, transactions)
      .expect_err("gap between nonces 0 and 2");
  }

  {
    let transactions =
      provided.iter().chain(unsigned.iter()).chain(signed.iter()).cloned().collect::<Box<_>>();
    for i in 0 .. transactions.len() {
      let mut transactions = transactions.clone();
      transactions[i].valid = false;
      Block::<TestTransaction>::verify_syntax_transactions(genesis, &transactions)
        .expect_err("invalid transaction");
    }
  }

  {
    let transactions = signed.iter().cloned().collect::<Box<_>>();
    for i in 0 .. transactions.len() {
      let mut transactions = transactions.clone();
      {
        let TransactionKind::Signed { scope: _, signed: Signed { signer, .. } } =
          &mut transactions[i].kind
        else {
          panic!("non-signed transaction in `signed`")
        };
        signer[0] ^= 1;
      }
      Block::<TestTransaction>::verify_syntax_transactions(genesis, &transactions)
        .expect_err("malleated signer");
    }
  }

  {
    let transactions = signed.iter().cloned().collect::<Box<_>>();
    for i in 0 .. transactions.len() {
      let mut transactions = transactions.clone();
      {
        let TransactionKind::Signed { scope: _, signed: Signed { signature, .. } } =
          &mut transactions[i].kind
        else {
          panic!("non-signed transaction in `signed`")
        };
        signature[0] ^= 1;
      }
      Block::<TestTransaction>::verify_syntax_transactions(genesis, &transactions)
        .expect_err("malleated signature");
    }
  }
}
