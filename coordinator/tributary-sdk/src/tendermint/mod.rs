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
use alloc::{boxed::Box, vec::Vec, collections::BTreeMap};
use std::{time::SystemTime, collections::HashMap};

use serai_db::{Get, Transaction as DbTxn, Db};

use ::tendermint::{Network, CommitFor, SlashReasonFor, InvalidBlock};

use crate::{
  ReadWrite as _, ReadWriteAsBorsh,
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

/// A wrapper around `HashMap` which caches the results of its functions.
pub(crate) struct ValidatorSet {
  validators: HashMap<[u8; 32], NonZero<u16>>,
  total_weight: NonZero<u16>,
  proposers: Box<[[u8; 32]]>,
}

impl ValidatorSet {
  fn new(validators: HashMap<[u8; 32], NonZero<u16>>) -> Self {
    use ::tendermint::ValidatorSet as _;

    let total_weight = validators.total_weight();
    /*
      TODO: This builds the cache by calling the underlying, yet the underlying continually ad-hocs
      builds this information, Directly build the cache here.
    */
    let proposers = {
      let mut proposers = Box::new_uninit_slice(usize::from(u16::from(total_weight)));
      let mut i = 0u16;
      for proposer in &mut proposers {
        i += 1;
        proposer.write(validators.proposer(
          ::tendermint::BlockNumber::from(NonZero::new(u64::from(i)).unwrap()),
          ::tendermint::RoundNumber::from(const { NonZero::new(1u64).unwrap() }),
        ));
      }
      // Safety: We just wrote to every entry of this slice
      unsafe { proposers.assume_init() }
    };

    Self { validators, total_weight, proposers }
  }
}

impl ::tendermint::ValidatorSet for ValidatorSet {
  type Validator = [u8; 32];

  fn total_weight(&self) -> NonZero<u16> {
    self.total_weight
  }

  fn validators(&self) -> impl IntoIterator<Item = &Self::Validator> {
    self.validators.keys()
  }

  fn weight(&self, validator: &Self::Validator) -> Option<NonZero<u16>> {
    self.validators.get(validator).copied()
  }

  fn proposer(
    &self,
    block_number: ::tendermint::BlockNumber,
    round_number: ::tendermint::RoundNumber,
  ) -> Self::Validator {
    let i = ((u64::from(block_number) - 1) % u64::from(u16::from(self.total_weight))) +
      ((u64::from(round_number) - 1) % u64::from(u16::from(self.total_weight)));
    let i = u16::try_from(i % u64::from(u16::from(self.total_weight))).unwrap();
    self.proposers[usize::from(i)]
  }
}

pub(crate) struct Tendermint<D, T: Transaction, M, N> {
  genesis: [u8; 32],
  genesis_time: u64,

  signature_scheme: SignatureScheme,
  _network: PhantomData<N>,

  db: D,
  blockchain: Blockchain<T>,
  validators: ValidatorSet,
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
    let signature_scheme = SignatureScheme::new(genesis, blockchain.validators().len());

    let validators = ValidatorSet::new(blockchain.validators().clone());

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
      validators,
      next_block_notification,

      slashes,
      mempool,
    }
  }
}

pin_project_lite::pin_project! {
  pub(crate) struct BlockProposal<MT, TS> {
    genesis: [u8; 32],
    parent: [u8; 32],
    minimum_time: Option<u64>,
    #[pin]
    minimum_time_future: Option<MT>,
    slashes: BTreeMap<[u8; 32], Slash>,
    #[pin]
    transactions: TS,

    // This is a weak form of entropy used to decide which validator to remove the transactions of
    // first. It doesn't have to satisfy any cryptographic requirements, it solely has to be
    // updated between blocks in order to ensure the validator removed from first isn't static.
    //
    // Only requiring weak entropy does mean this can theoretically be predicted by the adversary.
    // With the adversary selecting which validators have outstanding transactions, the adversary
    // can game which validators have their transactions removed (and therefore which have their
    // transactions remain). This is even easier since validators running this code will
    // consistently use the block number for 'entropy'. However, the practical effort of such an
    // attack is considered infeasible.
    weak_entropy: u64,
  }
}
impl<T: Transaction, MT: Future<Output = ()>, TS: Future<Output: IntoIterator<Item = T>>> Future
  for BlockProposal<MT, TS>
{
  type Output = ReadWriteAsBorsh<Block<T>>;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut projection = self.project();

    let block_time = {
      let Some(minimum_time) = *projection.minimum_time else {
        // If we were unable to determine the minimum time for this proposal, don't yield anything
        return Poll::Pending;
      };

      // Determine the current time, expressed as a block's time (milliseconds since the epoch)
      let block_time = {
        let time_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
        let Some(time_since_epoch_ms) =
          time_since_epoch.ok().and_then(|duration| u64::try_from(duration.as_millis()).ok())
        else {
          return Poll::Pending;
        };
        time_since_epoch_ms
      };

      if block_time < minimum_time {
        if let Some(minimum_time_future) = projection.minimum_time_future.as_mut().as_pin_mut() {
          // Poll the future so we establish a waker for our current context
          let Poll::Ready(()) = minimum_time_future.poll(cx) else {
            return Poll::Pending;
          };
          // Because this future has resolved, set it to `None` so we never call it again
          projection.minimum_time_future.set(None);
        }
        // Use the minimum time for the block's time
        minimum_time
      } else {
        // Since our time is greater than the minimum time, use our time
        block_time
      }
    };

    let (mut non_signed_transactions, mut transactions_by_signer) = {
      // Receive the transactions from the mempool
      let Poll::Ready(transactions) = projection.transactions.poll(cx) else {
        return Poll::Pending;
      };

      // Remove transactions from signers who have pending slashes
      let transactions = transactions.into_iter().filter(|tx| {
        if let TransactionKind::Signed {
          scope: _,
          signed: Signed { signer, nonce: _, signature: _ },
        } = tx.kind() &&
          projection.slashes.contains_key(&signer)
        {
          return false;
        }
        true
      });

      // Organize the transactions by their signer
      let mut non_signed_transactions = alloc::vec![];
      let mut transactions_by_signer = alloc::vec![];
      let mut signer_sizes = alloc::vec![];
      {
        let mut last_signer = None;
        let mut signer_full = false;
        for transaction in transactions {
          let TransactionKind::Signed { scope: _, signed: Signed { signer, .. } } =
            transaction.kind()
          else {
            non_signed_transactions.push(transaction);
            continue;
          };

          // This is correct by the requirement the mempool yield these transactions in order
          if Some(signer) != last_signer {
            transactions_by_signer.push(Vec::with_capacity(1));
            signer_sizes.push(Some(0usize));
            last_signer = Some(signer);
            signer_full = false;
          }

          if signer_full {
            continue;
          }

          let transactions_by_signer = transactions_by_signer.last_mut().unwrap();
          let signer_size = signer_sizes.last_mut().unwrap();

          /*
            Calculate this transaction's size.

            If we can't determine this transaction's size, for whatever reason, we skip it.
            However, as it may be a required predecessor to a following transaction, we mark this
            signer as 'full'.
          */
          let Ok(transaction_size) = crate::serialized_len(&transaction) else {
            signer_full = true;
            continue;
          };

          // Determine the new size of this signer's transactions
          let new_signer_size =
            (*signer_size).and_then(|signer_size| signer_size.checked_add(transaction_size));
          // We strictly require the new size of this signer's transactions be representable
          if new_signer_size.is_some() {
            *signer_size = new_signer_size;
            transactions_by_signer.push((transaction_size, transaction));
          } else {
            // If the size wasn't representable, mark this signer as full
            signer_full = true;
          }
        }
      }

      // If there's a block size limit...
      if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT {
        // And the signers' transactions exceed it...
        let signer_sizes = signer_sizes.into_iter().map(Option::unwrap).collect::<Vec<_>>();
        let approximate_block_size =
          signer_sizes.iter().fold((0usize, 0usize), |(mut lo, hi), size| {
            let carry;
            (lo, carry) = lo.overflowing_add(*size);
            /*
              This is guaranteed to not overflow as we're summing at most `u16::MAX` values, and
              `usize` is at least `u16`.
            */
            (lo, hi + usize::from(u8::from(carry)))
          });
        if let Some(mut size_to_trim) = {
          let (lo, borrow) = approximate_block_size.0.overflowing_sub(block_size_limit);
          let (hi, borrow) =
            approximate_block_size.1.overflowing_sub(usize::from(u8::from(borrow)));
          /*
            If this _does not_ have a borrow, we successfully subtracted the block's size limit
            from our approximate block size, and our approximate block size is greater than or
            equal to the block's size limit.
          */
          let size_to_trim = (!borrow).then_some((lo, hi));
          size_to_trim.filter(|size_to_trim| size_to_trim != &(0, 0))
        } && let Some(target_size_per_signer) = block_size_limit.checked_div(signer_sizes.len())
        {
          /*
            Remove transactions until either:
            - This signer only has one transaction left
            - This signer's transactions' size are less than the amortized capacity per signer
            - All transactions are less than the block's size limit

            This does not consider the block header's size, nor the size of the slashes. This isn't
            meant to ensure the resulting block is less than the block's size limit, solely be a
            rough first pass which does _most_ of the work in a fair manner.
          */
          'outer: for (mut size, transactions) in
            signer_sizes.into_iter().zip(&mut transactions_by_signer)
          {
            while (transactions.len() > 1) && (size > target_size_per_signer) {
              let (transaction_size, _transaction) = transactions.pop().unwrap();
              size = size.saturating_sub(transaction_size);

              let mut borrow;
              (size_to_trim.0, borrow) = size_to_trim.0.overflowing_sub(transaction_size);
              (size_to_trim.1, borrow) =
                size_to_trim.1.overflowing_sub(usize::from(u8::from(borrow)));
              if borrow || (size_to_trim == (0, 0)) {
                break 'outer;
              }
            }
          }
        }
      }

      (
        non_signed_transactions,
        transactions_by_signer
          .into_iter()
          .map(|transactions| {
            transactions
              .into_iter()
              .map(|(_transaction_size, transaction)| transaction)
              .collect::<Vec<_>>()
          })
          .filter(|transactions| !transactions.is_empty())
          .collect::<Vec<_>>(),
      )
    };
    let mut next_validator_to_remove_from =
      usize::try_from((*projection.weak_entropy) & u64::from(u16::MAX)).unwrap();

    let mut slashes = projection.slashes.values().cloned().collect::<Vec<_>>();

    let block = loop {
      match Block::instantiate(
        *projection.genesis,
        *projection.parent,
        block_time,
        slashes.clone().into_boxed_slice(),
        non_signed_transactions
          .iter()
          .chain(transactions_by_signer.iter().flatten())
          .cloned()
          .collect::<Box<[_]>>(),
      ) {
        Ok(block) => break block,
        Err(err) => {
          // If even an empty block is syntactically invalid, don't yield a proposal
          if slashes.is_empty() &&
            non_signed_transactions.is_empty() &&
            transactions_by_signer.iter().all(Vec::is_empty)
          {
            return Poll::Pending;
          }

          let mut size_to_trim = if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT &&
            let SyntacticError::ExceededSizeLimit { size: Some(size) } = err
          {
            size.checked_sub(block_size_limit)
          } else {
            None
          };

          /*
            If this block is syntactically invalid, assume the mempool provided invalid
            transactions _or_ this block is over the size limit. Either problem can be solved by
            popping transactions, except if over the size limit due to the slashes.

            This also smooths over any issues with the mempool, if it yielded invalid transactions
            or an invalid ordering.
          */

          /*
            Remove a transaction.

            This removes a validator's _last_ transaction in order to ensure it does not affect the
            ordering's validity.
          */
          let mut remove_transaction = || {
            /*
              Rotate which validator the transaction is removed from to prevent a single
              validator's transactions from exhausting a block's capacity.
            */
            let signer_to_remove_from =
              next_validator_to_remove_from.checked_rem(transactions_by_signer.len());
            next_validator_to_remove_from = next_validator_to_remove_from.wrapping_add(1);

            if let Some(signer_to_remove_from) = signer_to_remove_from {
              let transaction = transactions_by_signer[signer_to_remove_from].pop();
              if transactions_by_signer[signer_to_remove_from].is_empty() {
                transactions_by_signer.remove(signer_to_remove_from);
              }
              transaction
            } else {
              non_signed_transactions.pop()
            }
          };

          while {
            if let Some(removed_len) = if let Some(transaction) = remove_transaction() {
              crate::serialized_len(&transaction).ok()
            } else {
              /*
                If this block has no transactions, but has slashes, and is invalid, assume it's
                over the size limit and pop slashes until it's within the size limit.
              */
              slashes.pop().and_then(|slash| crate::serialized_len(&slash).ok())
            } {
              size_to_trim =
                size_to_trim.and_then(|size_to_trim| size_to_trim.checked_sub(removed_len));

              size_to_trim.is_some_and(|size_to_trim| size_to_trim > 0)
            } else {
              // We couldn't remove anything/we couldn't determine the size of what we removed
              false
            }
          } {}
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
    weak_entropy: u64,
  ) -> BlockProposal<N::Sleep, M::Future> {
    BlockProposal {
      genesis: self.genesis,
      parent,
      minimum_time,
      minimum_time_future: minimum_time.and_then(|minimum_time| {
        let minimum_system_time =
          SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(minimum_time))?;
        let time_remaining = minimum_system_time.duration_since(SystemTime::now()).ok()?;
        Some(N::sleep(time_remaining))
      }),
      slashes: self.slashes.clone(),
      transactions: self.mempool.transactions(parent),
      weak_entropy,
    }
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

  type BlockProposal = BlockProposal<N::Sleep, M::Future>;

  fn genesis(&self) -> &Self::Genesis {
    &self.genesis
  }

  fn validator_set(&self) -> &Self::ValidatorSet {
    &self.validators
  }

  fn signature_scheme(&self) -> &Self::SignatureScheme {
    &self.signature_scheme
  }

  fn validate(
    &mut self,
    proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>> {
    // TODO: Move this rule into `Blockchain::verify`?
    if self.blockchain.slashed(&self.db, proposer) {
      return core::future::ready(Err(InvalidBlock::Fatal));
    }
    if self.slashes.contains_key(&proposer) || self.mempool.censured(&self.db, proposer) {
      return core::future::ready(Err(InvalidBlock::Temporal));
    }

    core::future::ready(match self.blockchain.verify::<N>(&self.db, self.genesis_time, &block.0) {
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
    block: Self::Block,
    commit: CommitFor<Self>,
  ) -> impl Send + Future<Output = Self::BlockProposal> {
    let block = block.0;
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
      if Some(block.hash()) == crate::blockchain::Reader::<T>::tip(&self.db, self.genesis) {
        return self.block_proposal(hash, minimum_next_block_time, next_block_number);
      }

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
              core::future::pending::<Never>().await;
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
          core::future::pending::<Never>().await;
        }
      }

      self.block_proposal(hash, minimum_next_block_time, next_block_number)
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
