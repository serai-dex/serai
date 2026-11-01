//! The integration with Tendermint for consensus.
//!
//! `tributary-framework` makes use of `tendermint-consensus` for consensus, complimenting its
//! largely black-box view of consensus with the structure of a blockchain. This module implements
//! the necessary traits from `tendermint-consensus` for the two to work together, and defines the
//! [`Slash`] type.

use core::{marker::PhantomData, pin::Pin, time::Duration};
use alloc::{boxed::Box, collections::BTreeMap};
use std::time::SystemTime;

use serai_db::{Get, Transaction as DbTxn, Db};

use ::tendermint::{Network, CommitFor, SlashReasonFor, InvalidBlock};

use crate::{
  ReadWrite as _, ReadWriteAsBorsh,
  transaction::Transaction,
  block::{SyntacticError, SemanticError, EphemeralError, BlockError, Block},
  Blockchain,
};

mod validator_set;
pub(crate) use validator_set::ValidatorSet;

mod signature_scheme;
pub use signature_scheme::*;

mod slash;
pub use slash::Slash;

mod block_proposal;
use block_proposal::BlockProposal;

impl<T: Transaction> ::tendermint::Block for ReadWriteAsBorsh<Block<T>> {
  type Hash = [u8; 32];

  fn proposal_hash(&self) -> Self::Hash {
    use blake2::Digest as _;
    let mut digest = blake2::Blake2b256::new();
    self.0.write(crate::merkle::DigestWriter(&mut digest)).expect("`DigestWriter` is infallible");
    digest.finalize().into()
  }

  fn semantic_hash(&self) -> Self::Hash {
    self.0.hash()
  }
}

/// The [`tendermint_consensus::Commit`] type for a Tributary.
pub type Commit = ::tendermint::Commit<AggregateSignature>;

/// An abstraction over the mempool.
// TODO: This is currently solely a half-baked internal API
pub(crate) trait Mempool<T> {
  /// The container for transactions from the mempool.
  type Transactions: IntoIterator<Item = T>;
  /// The future for the transactions to include in the proposal for the next block.
  type Future: Future<Output = Self::Transactions>;
  /// Fetch transactions to include in the proposal for the next block.
  ///
  /// These transactions MUST be syntactically and semantically valid for the specified parent
  /// block. The transactions MUST be sorted but MAY exceed the block's size limit in their
  /// totality. Some transactions MAY be omitted from the resulting proposal.
  fn transactions(&mut self, parent_block: [u8; 32]) -> Self::Future;
  /// If a validator has been censured.
  fn censured(&self, getter: &impl Get, validator: [u8; 32]) -> bool;
  /// Censure a validator.
  fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]);
}

mod db {
  use super::*;

  serai_db::schema!(TributaryTendermint {
    PendingSlash: (genesis: [u8; 32], validator: [u8; 32]) -> ReadWriteAsBorsh<super::Slash>,
    Commit: (genesis: [u8; 32], block: [u8; 32]) -> super::Commit,
  });
}

pub(super) fn db_commit(getter: &impl Get, genesis: [u8; 32], block: [u8; 32]) -> Option<Commit> {
  db::Commit::get(getter, genesis, block)
}

pub(crate) struct Tendermint<D, T: Transaction, M, N> {
  genesis: [u8; 32],

  _network: PhantomData<N>,

  db: D,
  blockchain: Blockchain<T>,
  next_block_notification: async_channel::Receiver<async_channel::Sender<()>>,

  /// The mempool for slashes.
  ///
  /// This can also be considered a `BTreeSet<T>` where `<Slash as core::cmp::Ord>` is implemented
  /// by deferring to `<Slash::validator() as core::cmp::Ord>`.
  slashes: BTreeMap<[u8; 32], Slash>,
  /// The mempool for transactions.
  mempool: M,
}

impl<D: Db, T: Transaction, M, N> Tendermint<D, T, M, N> {
  pub(crate) fn new(
    db: D,
    genesis: [u8; 32],
    blockchain: Blockchain<T>,
    next_block_notification: async_channel::Receiver<async_channel::Sender<()>>,
    mempool: M,
  ) -> Self {
    let slashes = blockchain
      .validator_set()
      .as_ref()
      .keys()
      .copied()
      .filter_map(|validator| {
        db::PendingSlash::get(&db, genesis, validator).map(|slash| (validator, slash.0))
      })
      .collect::<BTreeMap<_, _>>();

    Self {
      genesis,

      _network: PhantomData,

      db,
      blockchain,
      next_block_notification,

      slashes,
      mempool,
    }
  }
}

impl<
  D: Db,
  T: Transaction,
  M: Mempool<T>,
  N: Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>>,
> Tendermint<D, T, M, N>
{
  /// An `Unpin` future for a proposal for the next block.
  ///
  /// If `minimum_time` is none, it's considered as not being representable, in which case no block
  /// should be proposed to maintain the system's soundness. The resulting future will never yield
  /// `Poll::Ready(block)`.
  pub(crate) fn block_proposal(
    &mut self,
    parent: [u8; 32],
    minimum_time: Option<u64>,
    weak_entropy: u64,
  ) -> Pin<Box<BlockProposal<N::Sleep, M::Future>>> {
    Box::pin(match minimum_time {
      Some(minimum_time) => BlockProposal::some::<T, N>(
        self.genesis,
        parent,
        minimum_time,
        self.slashes.clone(),
        self.mempool.transactions(parent),
        weak_entropy,
      ),
      // If we were unable to determine the minimum time for this proposal, don't yield anything
      None => BlockProposal::none(),
    })
  }
}

// TODO: Remove with Rust 1.100
trait FnOutput {
  type Output;
}
impl<R> FnOutput for fn() -> R {
  type Output = R;
}
type Never = <fn() -> ! as FnOutput>::Output;

type RWaB<T> = ReadWriteAsBorsh<T>;
impl<
  D: Send + Db,
  T: Send + Transaction,
  M: Send + Mempool<T>,
  N: Send + Network<[u8; 32], [u8; 64], AggregateSignature, RWaB<Block<T>>, Sleep: Send>,
> ::tendermint::Blockchain for Tendermint<D, T, M, N>
{
  type Validator = [u8; 32];
  type ValidatorSet = ValidatorSet;
  type SignatureScheme = SignatureScheme;
  type Genesis = [u8; 32];
  type Block = ReadWriteAsBorsh<Block<T>>;

  type BlockProposal = Pin<Box<BlockProposal<N::Sleep, M::Future>>>;

  fn genesis(&self) -> &Self::Genesis {
    &self.genesis
  }

  fn validator_set(&self) -> &Self::ValidatorSet {
    self.blockchain.validator_set()
  }

  fn signature_scheme(&self) -> &Self::SignatureScheme {
    self.blockchain.signature_scheme()
  }

  fn validate(
    &mut self,
    proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>> {
    if self.blockchain.slashed(&self.db, proposer) {
      return core::future::ready(Err(InvalidBlock::Fatal));
    }
    if self.slashes.contains_key(&proposer) || self.mempool.censured(&self.db, proposer) {
      return core::future::ready(Err(InvalidBlock::Temporal));
    }

    core::future::ready(match self.blockchain.verify::<N>(&self.db, &block.0) {
      Ok(()) => Ok(()),
      Err(BlockError::Ephemeral(_)) => Err(InvalidBlock::Temporal),
      Err(BlockError::Syntactic(_) | BlockError::Semantic(_)) => {
        // If block is invalid for syntactic or semantic reasons, censure
        let mut txn = self.db.txn();
        self.mempool.censure(&mut txn, proposer);
        txn.commit();

        Err(InvalidBlock::Fatal)
      }
    })
  }

  fn add_block(
    &mut self,
    ReadWriteAsBorsh(block): Self::Block,
    commit: CommitFor<Self>,
  ) -> impl Send + Future<Output = Self::BlockProposal> {
    let hash = block.hash();

    let next_block_number = u64::from(commit.block_number()).checked_add(1);

    let minimum_next_block_time = N::target_block_time()
      .and_then(|target_block_time| u64::try_from(target_block_time.as_millis()).ok())
      .and_then(|target_block_time| target_block_time.checked_add(block.time()));

    #[expect(clippy::async_yields_async)]
    async move {
      let Some(next_block_number) = next_block_number else {
        core::future::pending::<Never>().await
      };

      /*
        The Tendermint consensus process and the Tributary blockchain use independent transactions.
        The Tributary may run, adding the block, before the process reboots and Tendermint (once
        reinstantiated) tries to add the block again (as documented).

        Accordingly, if this is adding the block we already added, immediately short-circuit to the
        block proposal.
      */
      if Some(hash) == crate::blockchain::Reader::<T>::tip(&self.db, self.genesis) {
        return self.block_proposal(hash, minimum_next_block_time, next_block_number);
      }

      match self.blockchain.verify::<N>(&self.db, &block) {
        block_result @ (Ok(()) |
        Err(
          BlockError::Ephemeral(
            EphemeralError::NotLocallyProvidedTransaction { .. } | EphemeralError::Future,
          ) |
          BlockError::Semantic(SemanticError::DistinctProvided { .. }),
        )) => {
          // If this occurred in the future, sleep until it's valid
          if matches!(block_result, Err(BlockError::Ephemeral(EphemeralError::Future))) {
            if let Some(minimum_next_block_time) = minimum_next_block_time &&
              let Some(minimum_next_block_time) = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_millis(minimum_next_block_time))
            {
              if let Ok(time_remaining) = minimum_next_block_time.duration_since(SystemTime::now())
              {
                // Sleep until the next block's minimum time
                N::sleep(time_remaining).await;
              }
            } else {
              // If the amount of time in the future isn't representable, stall
              core::future::pending::<Never>().await;
            }
          }

          // Actually add the block
          {
            let mut txn = self.db.txn();
            for slash in block.slashes() {
              if self.slashes.remove(slash.validator()).is_some() {
                db::PendingSlash::del(&mut txn, self.genesis, *slash.validator());
              }
            }
            self.blockchain.add(&mut txn, &block);
            db::Commit::set(&mut txn, self.genesis, hash, &commit);
            txn.commit();
          }

          while let Ok(next_block_notification) = self.next_block_notification.try_recv() {
            let _ = next_block_notification.try_send(());
          }

          /*
            Sleep until the next block's minimum time before yielding back to the Tendermint
            consensus process.

            This causes the Tendermint consensus process to only start working on the next block
            _after_ the next block may be valid, preventing (or at least limiting) the initial
            attempts from failing in the time between when this block is added and when the next
            block can be added.

            This block of code is _solely_ intended to limit the initial attempts to achieve
            consensus on the next block from failing. The rate limiting of blocks, preventing a
            malicious supermajority from performing a DoS by flooding blocks, is handled _before_
            each block is added. The block proposal logic also performs its own handling of the
            minimum time for the next block to ensure it only creates valid proposals.
          */
          if let Some(minimum_next_block_time) = minimum_next_block_time &&
            let Some(minimum_next_block_time) =
              SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(minimum_next_block_time)) &&
            let Ok(time_remaining) = minimum_next_block_time.duration_since(SystemTime::now())
          {
            N::sleep(time_remaining).await;
          }

          self.block_proposal(hash, minimum_next_block_time, next_block_number)
        }

        Err(
          BlockError::Syntactic(
            SyntacticError::ExceededSizeLimit { .. } |
            SyntacticError::IncorrectContents |
            SyntacticError::AbsurdTime |
            SyntacticError::IncorrectOrderOfContents |
            SyntacticError::Transaction(_),
          ) |
          BlockError::Semantic(
            SemanticError::TooSoon |
            SemanticError::InvalidSlash { .. } |
            SemanticError::SlashAlreadyIncluded { .. } |
            SemanticError::UnsignedAlreadyIncluded { .. } |
            SemanticError::InvalidSigner { .. } |
            SemanticError::Gap { .. },
          ) |
          BlockError::Ephemeral(EphemeralError::UnexpectedParent),
        ) => {
          // Because an invalid block was added, stall the consensus process/block production
          core::future::pending::<Never>().await
        }
      }
    }
  }

  // TODO: This should be tracked such that the application may pass judgement
  fn missed_proposal(&self, _proposer: Self::Validator) {}

  fn slash(&mut self, validator: Self::Validator, slash_reason: SlashReasonFor<Self>) {
    // Check this validator hasn't already been slashed on-chain
    if self.blockchain.slashed(&self.db, validator) {
      return;
    }

    let slash = Slash { validator, slash_reason };
    let Ok(slash_size) = crate::serialized_len(&slash) else { return };

    let existing_slash_size = self
      .slashes
      .get(slash.validator())
      .and_then(|existing_slash| crate::serialized_len(existing_slash).ok());

    let mut txn = self.db.txn();
    if existing_slash_size.is_none() {
      self.mempool.censure(&mut txn, *slash.validator());
    }
    // If this validator already has a slash pending, keep whichever is smaller
    if existing_slash_size.is_none_or(|existing_slash_size| existing_slash_size > slash_size) {
      db::PendingSlash::set(&mut txn, self.genesis, *slash.validator(), (&slash).into());
      self.slashes.insert(*slash.validator(), slash);
    }
    txn.commit();
  }
}
