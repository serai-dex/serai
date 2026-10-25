#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::{
  pin::Pin,
  task::{Poll, Context},
  num::NonZero,
};
extern crate alloc;
use alloc::boxed::Box;
extern crate std;
use std::collections::HashMap;

use futures_core::stream::{Stream as _, FusedStream as _};

use zeroize::Zeroizing;
use ciphersuite::WrappedGroup;
use dalek_ff_group::Ristretto;

use serai_db::{Transaction as _, Db};

use ::tendermint::{Signer as _, Network};

mod read_write;
pub use read_write::*;

/// The specification and implementation of a Merkle tree.
pub mod merkle;
use merkle::*;

/// The functionality for transactions.
pub mod transaction;
use transaction::{Signed, TransactionKind};
pub use transaction::Transaction;

/// The functionality for blocks.
pub mod block;
pub use block::Block;

pub mod mempool;
use mempool::{MempoolError, MempoolNetwork, Mempool, MempoolConsumer};

mod blockchain;
use blockchain::{Reader, Blockchain};

mod tendermint;
use tendermint::{AggregateSignature, SignatureScheme, Tendermint};
pub use tendermint::Slash;

mod or;

type TendermintMessage<T> =
  ::tendermint::Message<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>>;

trait SendDb: Send + for<'db> Db<Transaction<'db>: Send> {}
impl<D: Send + for<'db> Db<Transaction<'db>: Send>> SendDb for D {}

struct AsyncAddToMempool<T> {
  transaction: T,
  bypass_rate_limit: bool,
  response: async_channel::Sender<Result<(), MempoolError>>,
}

pin_project_lite::pin_project! {
  struct MempoolFuture<D: SendDb, T: Transaction, MN: MempoolNetwork<T>> {
    db: D,
    #[pin]
    mempool: Mempool<D, T, MN>,
    #[pin]
    mempool_recv: async_channel::Receiver<AsyncAddToMempool<T>>,
  }
}

pin_project_lite::pin_project! {
  /// An instanced Tributary.
  ///
  /// This is a collection of futures which MUST be polled in order for the Tributary to make
  /// progress. It may be directly polled, acting as a single-threaded sequential executor for each
  /// of the contained futures, or unrolled via its `IntoIterator` implementation, allowing the
  /// futures to be individually spawned on an executor.
  pub struct Tributary<
    D: SendDb,
    T: Transaction,
    MN: MempoolNetwork<T>,
  > {
    #[pin]
    mempool: MempoolFuture<D, T, MN>,
    #[pin]
    tendermint: Pin<Box<dyn Future<Output = ()>>>,
    #[pin]
    handle: Pin<Box<dyn Future<Output = ()>>>,
  }
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
  MN: 'static + Send + Sync + MempoolNetwork<T>,
> Future for MempoolFuture<D, T, MN>
{
  type Output = ();
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut projection = self.project();

    let _: Poll<()> = projection.mempool.as_mut().poll(cx);
    if (!projection.mempool_recv.is_terminated()) &&
      let Poll::Ready(Some(AsyncAddToMempool { transaction, bypass_rate_limit, response })) =
        projection.mempool_recv.poll_next(cx)
    {
      let mut txn = projection.db.txn();
      let result = projection.mempool.add(&mut txn, transaction, bypass_rate_limit);
      txn.commit();

      let _ = response.try_send(result);
    }

    Poll::Pending
  }
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
  MN: 'static + Send + Sync + MempoolNetwork<T>,
> Future for Tributary<D, T, MN>
{
  type Output = ();
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let projection = self.project();

    let _: Poll<()> = projection.tendermint.poll(cx);
    let _: Poll<()> = projection.handle.poll(cx);
    let _: Poll<()> = projection.mempool.poll(cx);

    Poll::Pending
  }
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
  MN: 'static + Send + Sync + MempoolNetwork<T>,
> IntoIterator for Tributary<D, T, MN>
{
  type Item = Pin<Box<dyn Future<Output = ()>>>;
  type IntoIter = <[Self::Item; 3] as IntoIterator>::IntoIter;
  fn into_iter(self) -> Self::IntoIter {
    let Self { tendermint, handle, mempool } = self;
    [tendermint, handle, Box::pin(mempool)].into_iter()
  }
}

/// An error when instantiating the Tributary.
pub enum TributaryError {
  /// The (target) block time wasn't representable.
  UnrepresentableBlockTime,
  /// The provided key didn't correspond to a validator.
  NotValidator,
}

/// A handle to an instanced Tributary.
#[derive(Clone)]
pub struct TributaryHandle<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
> {
  db: D,
  genesis: [u8; 32],

  validator: [u8; 32],

  blocks_behind: async_channel::Sender<async_channel::Sender<u64>>,

  sync: async_channel::Sender<(Block<T>, crate::tendermint::Commit)>,
  message: async_channel::Sender<TendermintMessage<T>>,
  mempool: async_channel::Sender<AsyncAddToMempool<T>>,
  censure: async_channel::Sender<([u8; 32], async_channel::Sender<()>)>,

  next_block_notification: async_channel::Sender<async_channel::Sender<()>>,
}

#[expect(private_bounds)]
impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
  MN: 'static + Send + Sync + MempoolNetwork<T>,
> Tributary<D, T, MN>
{
  /// Instance a Tributary.
  ///
  /// This MUST be the only Tributary instanced with this `genesis` value. It will be reloaded from
  /// the database if prior instanced. For further context on the limitations of this, please defer
  /// to the limitations placed upon [`::tendermint::Tendermint`].
  ///
  /// The `genesis` argument will be expanded to a 32-byte genesis by prefixing 16 `0`s.
  ///
  /// `genesis_time` is expressed in milliseconds since the epoch and used to limit the minimum
  /// time blocks may be published with. This prevents a malicious supermajority from backdating
  /// blocks, allowing flooding the honest minority with valid blocks which still respect the
  /// minimum spacing between blocks. It is optional as it is not strictly required, but it is
  /// practically required for resilience against a dishonest supermajority (who can compromise the
  /// integrity of the Tributary in general). Whatever value is set, it MUST be consistent across
  /// participants.
  ///
  /// `validators` represents the validators present in the Tributary (keyed by their Ristretto
  /// public keys, valued by their weight in the consensus process). It MUST be a valid value for
  /// the [`::tendermint::ValidatorSet`] trait.
  ///
  /// `key` is the validator's Ristretto private key.
  ///
  /// `mempool_rate_limit` is the maximum amount of transactions each validator may have pending
  /// within the mempool. It may be locally configured independently of other validators. It does
  /// not apply to provided nor unsigned transactions which are privileged within the Tributary.
  #[expect(clippy::too_many_arguments)]
  pub async fn new<
    N: 'static
      + Send
      + Sync
      + Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>, Sleep: Send>,
  >(
    db: D,
    genesis: [u8; 16],
    genesis_time: Option<u64>,
    validators: HashMap<[u8; 32], NonZero<u16>>,
    tendermint_network: N,
    mempool_network: MN,
    key: Zeroizing<<Ristretto as WrappedGroup>::F>,
    mempool_rate_limit: usize,
  ) -> Result<(Self, TributaryHandle<D, T>), TributaryError> {
    /*
      Expand the 16-byte genesis DST into a 32-byte 'hash'.

      This isn't considered a hash, solely an element in the same 32-byte domain as a hash
      (allowing it to be specified as the 'parent' for the first actual block on the blockchain).

      Tendermint allows the genesis to be an arbitrary DST value but the Tributary requires it not
      collide with an actual block's hash. The following expansion sets the first 16 bytes to `0`,
      meaning a collision would require 128 bits of effort (as the security of the rest of the
      cryptography in the Tributary requires).
    */
    let genesis = {
      let mut genesis_32 = [0; 32];
      genesis_32[16 ..].copy_from_slice(&genesis);
      genesis_32
    };

    let genesis_time = genesis_time.unwrap_or(0);

    // TODO: This is the maximum of the bound internal to the `tendermint-machine` library
    let (sync_send, sync_recv) =
      async_channel::bounded::<(Block<T>, crate::tendermint::Commit)>(64);
    let (message_send, message_recv) = async_channel::bounded::<
      ::tendermint::MessageFor<Tendermint<D, T, MempoolConsumer<T>, N>>,
    >(2 * validators.len());

    let (mempool_send, mempool_recv) =
      async_channel::bounded::<AsyncAddToMempool<T>>(mempool_rate_limit.max(8));

    let (censure_send, censure_recv) =
      async_channel::bounded::<([u8; 32], async_channel::Sender<()>)>(validators.len());

    let (mempool, mempool_consumer) = Mempool::new(
      db.clone(),
      genesis,
      validators.keys().copied(),
      mempool_network,
      censure_recv,
      mempool_rate_limit,
    );

    let (blocks_behind_send, blocks_behind_recv) =
      async_channel::bounded::<async_channel::Sender<u64>>(1);

    let signer = SignatureScheme::new(genesis, validators.len()).signer(key);
    let validator = signer.validator();
    if !validators.contains_key(&validator) {
      Err(TributaryError::NotValidator)?;
    }

    let (next_block_notification, (mut tendermint_handle, tendermint)) = {
      let blockchain = Blockchain::new(&db, genesis, validators);

      let (tip, minimum_next_block_time) = {
        let tip = blockchain.tip(&db);
        let target_block_time = u64::try_from(
          N::target_block_time().ok_or(TributaryError::UnrepresentableBlockTime)?.as_millis(),
        )
        .map_err(|_| TributaryError::UnrepresentableBlockTime)?;
        let minimum_next_block_time = tip
          .as_ref()
          .map(|tip| tip.time().checked_add(target_block_time))
          .unwrap_or(Some(genesis_time));
        let tip = tip.map(|block| block.hash()).unwrap_or(genesis);
        (tip, minimum_next_block_time)
      };

      /*
        In practice, this is bounded by the amount of handles which simultaneously exist,
        preventing concerns with its memory usage. If the caller did cause this channel to be an
        effective DoS, it'd be because they've already created an amount of handles which are an
        effective DoS.
      */
      let (next_block_notification_send, next_block_notification_recv) =
        async_channel::unbounded::<async_channel::Sender<()>>();

      let mut tendermint = Tendermint::<_, _, _, N>::new(
        genesis,
        genesis_time,
        db.clone(),
        blockchain,
        next_block_notification_recv,
        mempool_consumer,
      );
      let proposal = tendermint.block_proposal(tip, minimum_next_block_time, 0);

      (
        next_block_notification_send,
        ::tendermint::Tendermint::process(
          tendermint,
          signer,
          db.clone(),
          tendermint_network,
          proposal,
        )
        .await,
      )
    };

    let handle = Box::pin(async move {
      loop {
        let result: Result<(), ::tendermint::ProcessTerminated> = match (or::Or {
          f1: or::Or { f1: sync_recv.recv(), f2: message_recv.recv() },
          f2: blocks_behind_recv.recv(),
        })
        .await
        {
          or::Either::L(or::Either::L(Ok((block, commit)))) => {
            tendermint_handle.sync(ReadWriteAsBorsh(block), commit).await
          }
          or::Either::L(or::Either::R(Ok(message))) => tendermint_handle.message(message).await,

          or::Either::R(Ok(blocks_behind)) => {
            // Ignore the error in case the future was cancelled
            let _ = blocks_behind.try_send({
              let observed_block_number = u64::from(tendermint_handle.observed_block_number());
              let block_number = u64::from(tendermint_handle.block_number());
              observed_block_number.saturating_sub(block_number)
            });
            Ok(())
          }

          // If all of the handles were dropped, we consider the process terminated
          or::Either::L(or::Either::L(Err(_)) | or::Either::R(Err(_))) | or::Either::R(Err(_)) => {
            Err(::tendermint::ProcessTerminated)
          }
        };

        if let Err(::tendermint::ProcessTerminated) = result {
          core::future::pending::<()>().await;
        }
      }
    });

    Ok((
      Self {
        tendermint: Box::pin(tendermint),
        handle,
        mempool: MempoolFuture { db: db.clone(), mempool, mempool_recv },
      },
      TributaryHandle {
        db,
        genesis,

        validator,

        blocks_behind: blocks_behind_send,

        sync: sync_send,
        message: message_send,
        mempool: mempool_send,
        censure: censure_send,

        next_block_notification,
      },
    ))
  }
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: 'static + Send + Sync + Transaction,
> TributaryHandle<D, T>
{
  /// The Tributary's genesis.
  pub fn genesis(&self) -> [u8; 32] {
    self.genesis
  }

  /// The Tributary's tip block.
  ///
  /// This is read from the database and is accordingly the last _committed_ block.
  pub fn tip(&self) -> Option<[u8; 32]> {
    Reader::<T>::tip(&self.db, self.genesis)
  }

  /// The amount of blocks the local Tributary is missing in comparison to the current consensus
  /// efforts.
  ///
  /// This is derivative of [`::tendermint::TendermintHandle::observed_block_number`], a method
  /// which allows the local process to observe the block validators are obtaining consensus over.
  /// It is not intended to be an explicit counter of the amount of blocks to explicitly sync,
  /// solely a hint.
  pub async fn blocks_behind(&self) -> u64 {
    let (send, recv) = async_channel::bounded(1);
    let _ = self.blocks_behind.send(send).await;
    match recv.recv().await {
      Ok(blocks_behind) => blocks_behind,
      Err(_) => core::future::pending().await,
    }
  }

  /// A block on the Tributary, identified by its hash.
  ///
  /// This returns `None` if the block wasn't committed on this Tributary.
  pub fn block(&self, hash: [u8; 32]) -> Option<Block<T>> {
    Reader::<T>::block(&self.db, self.genesis, hash)
  }
  /// The commit for a block on the Tributary.
  ///
  /// This returns `None` if no commit was saved for this block.
  pub fn commit(&self, block: [u8; 32]) -> Option<crate::tendermint::Commit> {
    Reader::<T>::commit(&self.db, self.genesis, block)
  }
  /// The block after a block on the Tributary.
  ///
  /// This returns `None` if either:
  /// - The parent block (identified by its hash) wasn't committed on this Tributary
  /// - It has no child block committed on the Tributary
  pub fn block_after(&self, parent: [u8; 32]) -> Option<[u8; 32]> {
    Reader::<T>::block_after(&self.db, self.genesis, parent)
  }

  /// Handle a consensus message.
  ///
  /// This will return once the message has been queued to be handled, offering no inspection
  /// into when that queue is consumed or if the queued message was valid.
  #[expect(private_interfaces)]
  pub async fn message(&self, message: TendermintMessage<T>) {
    /*
      Queueing into an open channel (with no observability into when the queue is consumed from) is
      considered equivalent to not queueing into a closed channel (a queue which will never be
      consumed from). All values are still handled in order, without omission, whenever (or if
      ever) handled. This lets us igore any error here.
    */
    let _ = self.message.send(message).await;
  }

  /// Explicitly sync a block.
  ///
  /// This is intended to be used when a Tributary is behind, unable to simply observe blocks as
  /// they're produced by the consensus process. The block will be queued to be verified/added and
  /// only actually added if valid.
  ///
  /// This will return once the block has been queued to be verified/added, offering no inspection
  /// into when that queue is consumed or if the queued block was valid.
  pub async fn sync(&self, block: Block<T>, commit: crate::tendermint::Commit) {
    /*
      Queueing into an open channel (with no observability into when the queue is consumed from) is
      considered equivalent to not queueing into a closed channel (a queue which will never be
      consumed from). All values are still handled in order, without omission, whenever (or if
      ever) handled. This lets us igore any error here.
    */
    let _ = self.sync.send((block, commit)).await;
  }

  /// Publish a transaction into the Tributary's mempool.
  ///
  /// This is used to publish a transaction, regardless of its kind. `Provided` transactions are
  /// intended to only be provided by the local node however, meaning the caller MUST check the
  /// kind of a transaction and its origin _before_ calling this method.
  ///
  /// The mempool's rate limit will be bypassed if the transaction's signer is the Tributary's
  /// validator, ensuring the local validator can publish their own transactions without needing to
  /// implement an additional buffer.
  pub async fn transaction(&self, transaction: T) -> Result<(), MempoolError> {
    let bypass_rate_limit =
      if let TransactionKind::Signed { signed: Signed { signer, .. }, .. } = transaction.kind() {
        signer == self.validator
      } else {
        true
      };

    let (response_send, response_recv) = async_channel::bounded(1);
    let _ = self
      .mempool
      .send(AsyncAddToMempool { transaction, bypass_rate_limit, response: response_send })
      .await;
    match response_recv.recv().await {
      Ok(result) => result,
      /*
        If the channel was closed, the mempool was dropped, and this publication won't occur.

        We yield `Pending` infinitely to reflect how this publication will never be ready. While
        the alternative would to be return an error, we presume that applications won't drop the
        mempool, letting us simplify the API a bit.
      */
      Err(_) => core::future::pending().await,
    }
  }

  /// Censure a validator.
  ///
  /// This will prevent voting for block proposals from this validator and not populate their
  /// transactions within the mempool. It only applies to the local view and doesn't have to
  /// performed in any synchrony with other validators.
  pub async fn censure(&self, validator: [u8; 32]) {
    let (censured_send, censured_recv) = async_channel::bounded::<()>(1);
    let _ = self.censure.send((validator, censured_send)).await;
    match censured_recv.recv().await {
      Ok(()) => {}
      /*
        If the channel was closed, this validator won't have the censure applied, so this function
        should never return (signifying the censure was applied).

        We _could_ also propagate an error to signify the Tributary is no longer running, but it
        isn't worth the API complexity.
      */
      Err(_) => core::future::pending().await,
    }
  }

  /// A future which resolves when the next block is added to the Tributary.
  pub fn next_block_notification(&self) -> impl Send + Sync + Future<Output = ()> {
    let (next_block_notification_send, next_block_notification_recv) =
      async_channel::bounded::<()>(1);
    let _ = self.next_block_notification.try_send(next_block_notification_send);
    async move {
      match next_block_notification_recv.recv().await {
        Ok(()) => {}
        /*
          If the channel was closed, there won't be any more blocks added, so this notification
          should never resolve.

          We _could_ also propagate an error to signify the Tributary is no longer running, but it
          isn't worth the API complexity.
        */
        Err(_) => core::future::pending().await,
      }
    }
  }
}
