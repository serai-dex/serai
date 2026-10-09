//! The integration with Tendermint for consensus.
//!
//! `tributary-sdk` makes use of `tendermint-machine` for consensus, complimenting its largely
//! black-box view of consensus with the structure of a blockchain. This module implements the
//! necessary traits from `tendermint-machine` for the two to work together, and defines the
//! [`Slash`] type.

use core::{
  marker::PhantomData,
  pin::Pin,
  task::{Poll, Context},
  num::NonZero,
  time::Duration,
};
use alloc::{vec::Vec, collections::BTreeMap};
use std::{time::SystemTime, collections::HashMap};

use serai_db::{Get, Transaction as DbTxn, Db};

use ::tendermint::{Network, CommitFor, SlashReasonFor, InvalidBlock};

use crate::{
  ReadWriteAsBorsh,
  transaction::{Signed, TransactionKind, Transaction},
  block::{SyntacticError, SemanticError, EphemeralError, BlockError, Block},
  Blockchain,
};

mod signature_scheme;
pub use signature_scheme::*;

mod slash;
pub use slash::Slash;

serai_db::schema!(TributaryTendermint {
  PendingSlash: (genesis: [u8; 32], validator: [u8; 32]) -> ReadWriteAsBorsh<super::Slash>,
  PendingSlashes: (genesis: [u8; 32]) -> Vec<[u8; 32]>,
});

impl<T: Transaction> ::tendermint::Block for ReadWriteAsBorsh<Block<T>> {
  type Hash = [u8; 32];
  fn hash(&self) -> Self::Hash {
    self.0.hash()
  }
}

/// The [`tendermint_machine::Commit`] type for a Tributary.
pub type Commit = ::tendermint::Commit<AggregateSignature>;

pub(crate) trait Mempool<T> {
  /// The container for transactions from the mempool.
  type Transactions: IntoIterator<Item = T>;
  /// The future for the transactions to include in the proposal for the next block.
  type Future: Future<Output = Self::Transactions>;
  /// Fetch transactions to include in the proposal for the next block.
  ///
  /// These transactions MUST be syntactically and semantically valid for the specified parent
  /// block. The transactions MUST be sorted but MAY exceed the block's size limit in their
  /// totality. Some transactions MAY not be included in the resulting proposal.
  fn transactions(&mut self, parent_block: [u8; 32]) -> Self::Future;
  /// If a validator has been censured.
  fn censured(&self, getter: &impl Get, validator: [u8; 32]) -> bool;
  /// Censure a validator.
  fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]);
}

pub(crate) struct Tendermint<D, T: Transaction, M, N> {
  genesis: [u8; 32],
  genesis_time: u64,

  signature_scheme: SignatureScheme,
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
    genesis: [u8; 32],
    genesis_time: u64,
    db: D,
    blockchain: Blockchain<T>,
    next_block_notification: async_channel::Receiver<async_channel::Sender<()>>,
    mempool: M,
  ) -> Self {
    let signature_scheme = SignatureScheme::new(genesis);

    let slashes = PendingSlashes::get(&db, genesis)
      .into_iter()
      .flatten()
      .map(|validator| {
        let slash = PendingSlash::get(&db, genesis, validator)
          .expect("slash in mempool wasn't saved to disk")
          .0;
        (validator, slash)
      })
      .collect::<BTreeMap<_, _>>();

    Self {
      genesis,
      genesis_time,

      signature_scheme,
      _network: PhantomData,

      db,
      blockchain,
      next_block_notification,

      slashes,
      mempool,
    }
  }
}

pin_project_lite::pin_project! {
  pub(crate) struct BlockProposal<F> {
    genesis: [u8; 32],
    parent: [u8; 32],
    minimum_time: Option<u64>,
    slashes: BTreeMap<[u8; 32], Slash>,
    #[pin]
    transactions: F,
  }
}
impl<T: Transaction, F: Future<Output: IntoIterator<Item = T>>> Future for BlockProposal<F> {
  type Output = ReadWriteAsBorsh<Block<T>>;
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut transactions = {
      // Receive the transactions from the mempool
      let Poll::Ready(transactions) = self.as_mut().project().transactions.poll(cx) else {
        return Poll::Pending;
      };
      // Remove transactions from signers who have pending slashes
      let transactions = transactions.into_iter().filter(|tx| {
        if let TransactionKind::Signed {
          scope: _,
          signed: Signed { signer, nonce: _, signature: _ },
        } = tx.kind() &&
          self.slashes.contains_key(&signer)
        {
          return false;
        }
        true
      });
      transactions.collect::<Vec<_>>()
    };

    let mut slashes = self.slashes.values().cloned().collect::<Vec<_>>();

    let block = loop {
      match Block::instantiate(
        self.genesis,
        self.parent,
        {
          use std::time::SystemTime;
          let time_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
          let Some(time_since_epoch_ms) =
            time_since_epoch.ok().and_then(|duration| u64::try_from(duration.as_millis()).ok())
          else {
            return Poll::Pending;
          };
          let Some(minimum_time) = self.minimum_time else { return Poll::Pending };
          time_since_epoch_ms.max(minimum_time)
        },
        slashes.clone().into_boxed_slice(),
        transactions.clone().into_boxed_slice(),
      ) {
        Ok(block) => break block,
        Err(_) => {
          // If even an empty block is syntactically invalid, don't yield a proposal
          if slashes.is_empty() && transactions.is_empty() {
            return Poll::Pending;
          }

          /*
            If this block is syntactically invalid, assume the mempool provided invalid
            transactions _or_ this block is over the size limit due to also including the slashes.
            Either problem can be solved by popping transactions.
          */
          if !transactions.is_empty() {
            transactions.pop();
          } else {
            /*
              If this block has no transactions, but has slashes, and is invalid, assume it's over
              the size limit and pop slashes until it's within the size limit.
            */
            slashes.pop();
          }
        }
      }
    };

    Poll::Ready(ReadWriteAsBorsh(block))
  }
}

impl<
  D: Db,
  T: Transaction,
  M: Mempool<T>,
  N: Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>>,
> Tendermint<D, T, M, N>
{
  pub(crate) fn block_proposal(
    &mut self,
    parent: [u8; 32],
    minimum_time: Option<u64>,
  ) -> BlockProposal<M::Future> {
    BlockProposal {
      genesis: self.genesis,
      parent,
      minimum_time,
      slashes: self.slashes.clone(),
      transactions: self.mempool.transactions(parent),
    }
  }
}

type RWaB<T> = ReadWriteAsBorsh<T>;
impl<
  D: Send + Db,
  T: Send + Transaction,
  M: Send + Mempool<T>,
  N: Send + Network<[u8; 32], [u8; 64], AggregateSignature, RWaB<Block<T>>, Sleep: Send>,
> ::tendermint::Blockchain for Tendermint<D, T, M, N>
{
  type Validator = [u8; 32];
  // TODO
  type ValidatorSet = HashMap<Self::Validator, NonZero<u16>>;
  type SignatureScheme = SignatureScheme;
  type Genesis = [u8; 32];
  type Block = ReadWriteAsBorsh<Block<T>>;

  type BlockProposal = BlockProposal<M::Future>;

  fn genesis(&self) -> &Self::Genesis {
    &self.genesis
  }

  fn validator_set(&self) -> &Self::ValidatorSet {
    self.blockchain.validators()
  }

  fn signature_scheme(&self) -> &Self::SignatureScheme {
    &self.signature_scheme
  }

  fn validate(
    &mut self,
    proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>> {
    if self.blockchain.slashed(&self.db, proposer) ||
      self.slashes.contains_key(&proposer) ||
      self.mempool.censured(&self.db, proposer)
    {
      return core::future::ready(Err(InvalidBlock));
    }

    let valid = self.blockchain.verify::<N>(&self.db, self.genesis_time, &block.0);
    // If block is invalid for syntactic or semantic reasons, censure
    match valid {
      Ok(()) | Err(BlockError::Ephemeral(_)) => {}
      Err(BlockError::Syntactic(_) | BlockError::Semantic(_)) => {
        let mut txn = self.db.txn();
        self.mempool.censure(&mut txn, proposer);
        txn.commit();
      }
    }
    core::future::ready(valid.map_err(|_| InvalidBlock))
  }

  fn add_block(
    &mut self,
    block: Self::Block,
    commit: CommitFor<Self>,
  ) -> impl Send + Future<Output = Self::BlockProposal> {
    let block = block.0;
    let hash = block.hash();

    let minimum_next_block_time = N::target_block_time()
      .and_then(|target_block_time| u64::try_from(target_block_time.as_millis()).ok())
      .and_then(|target_block_time| target_block_time.checked_add(block.time()));

    #[expect(clippy::async_yields_async)]
    async move {
      let verify_result = self.blockchain.verify::<N>(&self.db, self.genesis_time, &block);
      match &verify_result {
        Ok(()) |
        Err(
          BlockError::Ephemeral(
            EphemeralError::NotLocallyProvidedTransaction { .. } | EphemeralError::Future,
          ) |
          BlockError::Semantic(SemanticError::DistinctProvided { .. }),
        ) => {
          // If this occurred in the future, sleep until it's valid
          if matches!(verify_result, Err(BlockError::Ephemeral(EphemeralError::Future))) {
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
              core::future::pending::<()>().await;
            }
          }

          // Actually add the block
          let mut txn = self.db.txn();

          for slash in block.slashes() {
            if self.slashes.remove(slash.validator()).is_some() {
              PendingSlash::del(&mut txn, self.genesis, *slash.validator());
            }
          }
          PendingSlashes::set(
            &mut txn,
            self.genesis,
            &self.slashes.keys().copied().collect::<Vec<_>>(),
          );

          self.blockchain.add(&mut txn, &block, Some(&commit));

          txn.commit();

          while let Ok(next_block_notification) = self.next_block_notification.try_recv() {
            let _ = next_block_notification.try_send(());
          }
        }
        Err(
          BlockError::Syntactic(
            SyntacticError::ExceededSizeLimit |
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
          core::future::pending::<()>().await;
        }
      }

      self.block_proposal(hash, minimum_next_block_time)
    }
  }

  // TODO
  fn missed_proposal(&self, _proposer: Self::Validator) {}

  fn slash(&mut self, validator: Self::Validator, slash_reason: SlashReasonFor<Self>) {
    // Check this validator hasn't already been slashed on-chain
    if self.blockchain.slashed(&self.db, validator) {
      return;
    }

    let slash = Slash { validator, slash_reason };
    let Ok(serialized_slash_len) = crate::serialized_len(&slash) else { return };

    let existing_slash_len = self
      .slashes
      .get(slash.validator())
      .and_then(|existing_slash| crate::serialized_len(existing_slash).ok());

    let mut txn = self.db.txn();
    // If this validator already has a slash pending, keep whichever is smaller
    if existing_slash_len.is_none_or(|existing_slash_len| existing_slash_len > serialized_slash_len)
    {
      PendingSlash::set(&mut txn, self.genesis, *slash.validator(), (&slash).into());
      self.slashes.insert(*slash.validator(), slash);
    }
    // If this validator hadn't been prior slashed, update the list of slashed validators
    if existing_slash_len.is_none() {
      PendingSlashes::set(
        &mut txn,
        self.genesis,
        &self.slashes.keys().copied().collect::<Vec<_>>(),
      );
    }
    txn.commit();
  }
}
