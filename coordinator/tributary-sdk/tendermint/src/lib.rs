#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use core::{time::Duration, future::Future};

mod or;
use or::*;

mod timeout;
use timeout::*;

mod validators;
pub use validators::*;

mod commit;
pub use commit::*;

mod blockchain;
pub use blockchain::*;

mod message;
pub use message::*;

mod slash_reason;
pub use slash_reason::*;

#[cfg(feature = "std")]
mod state;
#[cfg(feature = "std")]
use state::*;

/// A view over the network used for consensus.
pub trait Network<V: Validator, S: Signature, A: AggregateSignature, B: Block> {
  /// The expected average-case latency of the network.
  ///
  /// This should be sufficient for a supermajority of validators to communicate, in the average
  /// case, as necessary to perform the consensus protocol. If the real-world latency exceeds this
  /// amount of time, the attempt to finalize a block will fail, and a new round will begin with an
  /// increased amount of latency. Accordingly, setting this to too optimistic of a value will
  /// increase the amount of failures.
  ///
  /// The derivatives of this MAY be limited to the bounds of the internal representations used for
  /// time.
  const LATENCY_TIME: Duration;

  /// The expected maximum amount of time to download a block.
  ///
  /// The derivatives of this MAY be limited to the bounds of the internal representations used for
  /// time.
  const BLOCK_DOWNLOADING_TIME: Duration;

  /// The expected maximum amount of time to process a block.
  ///
  /// This is also used as a timeout for fetching the block proposal, if it isn't ready yet.
  ///
  /// The derivatives of this MAY be limited to the bounds of the internal representations used for
  /// time.
  const BLOCK_PROCESSING_TIME: Duration;

  /// The future returned by [`Network::sleep`].
  type Sleep: Future<Output = ()>;

  /// An asynchronous implementation of [`std::thread::sleep`].
  ///
  /// This MUST be cancel-safe.
  fn sleep(duration: Duration) -> Self::Sleep;

  /// Broadcast a message to the other validators.
  ///
  /// Examples of broadcast include sending this message via peer-to-peer channels to all other
  /// validators, or publishing this message to a gossip network where it can be reasonably assumed
  /// to be delivered to all other validators. It does not have to achieve a formal definition of
  /// broadcast with any specific security properties, though failure for this message to be
  /// delivered to a sufficient amount of other validators in a timely fashion will cause consensus
  /// to stall until the timeout for a round exceeds the latency of this network.
  ///
  /// This DOES NOT have to be cancel-safe.
  fn broadcast(&mut self, message: Message<V, S, A, B>) -> impl Send + Future<Output = ()>;
}

#[cfg(feature = "std")]
mod tendermint {
  use core::{
    sync::atomic::{Ordering, AtomicU64},
    future::Future,
    num::NonZero,
  };
  use alloc::sync::Arc;

  /*
    We use `async-channel`, not `futures-channel`, as neither document/guarantee cancel safety.
    However, `async-channel` has [this issue](https://github.com/smol-rs/async-channel/issues/111)
    for which notgull confirms [`async_channel::Recv`] is cancel-safe:

    https://github.com/smol-rs/async-channel/issues/111#issuecomment-3459124415

    We expect this property, causing us to use `async-channel`.
  */
  use async_channel::{Sender, Receiver};

  use borsh::{BorshSerialize, BorshDeserialize};
  use serai_db::{Transaction as _, Db};

  use crate::{
    BlockNumber, ValidatorSet as _, SignatureScheme, Block, CommitFor, Blockchain, MessageFor,
    MessageError, Signer, Network, State, Or,
  };

  /// The Tendermint process.
  ///
  /// This is expected to drive the underlying blockchain, adding blocks to it as produced by
  /// itself _and as received from an external sync loop_ (which is not implemented here).
  pub struct Tendermint;

  /// The handle for the Tendermint process.
  pub struct TendermintHandle<B: Blockchain> {
    block_number: Arc<AtomicU64>,
    observed_block_number: Arc<AtomicU64>,
    sync: Sender<(B::Block, CommitFor<B>)>,
    message: Sender<MessageFor<B>>,
  }

  struct TendermintProcess<B: Blockchain, S, D, N> {
    sync: Receiver<(B::Block, CommitFor<B>)>,
    message: Receiver<MessageFor<B>>,

    state: State<B>,
    blockchain: B,
    signer: S,
    db: D,
    network: N,
  }

  impl<
    B: Blockchain<
        Validator: BorshSerialize + BorshDeserialize,
        SignatureScheme: SignatureScheme<
          Signature: BorshSerialize + BorshDeserialize,
          AggregateSignature: BorshSerialize + BorshDeserialize,
        >,
        Block: BorshSerialize + BorshDeserialize + Block<Hash: BorshSerialize + BorshDeserialize>,
      >,
    S: Signer<
        Validator = B::Validator,
        Signature = <B::SignatureScheme as SignatureScheme>::Signature,
      >,
    D: Db,
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  > TendermintProcess<B, S, D, N>
  {
    async fn run(mut self) {
      loop {
        /*
          We use our `Or` future to implement a select, where our `Or` is documented to prefer `f1`
          to `f2`, causing these to be polled in the order they're written.

          Receiving from the channels is cancel-safe, as is our own future to check for timeouts.
        */
        let tick = (Or {
          f1: Or {
            // Check for a synced block, which makes this entire consensus process immaterial
            f1: self.sync.recv(),
            /*
              Check if any timeouts have expired.

              We give this priority so if we reload from the database, this is consistently handled
              independent of any messages are available.
            */
            f2: self.state.timeout::<N, _>(&self.blockchain, &self.signer),
          },
          // Check for a received message, which may advance this consensus process
          f2: self.message.recv(),
        })
        .await;

        match tick {
          crate::or::Either::L(crate::or::Either::L(Ok((ref block, ref commit)))) => {
            // TODO: Remove these `Clone`s
            let block = block.clone();
            let commit = commit.clone();
            drop(tick);

            if commit.block_number != self.state.block_number() {
              continue;
            }
            if !commit.verify(
              self.blockchain.validator_set(),
              self.blockchain.signature_scheme(),
              self.blockchain.genesis(),
              block.hash(),
            ) {
              continue;
            }

            let mut txn = self.db.txn();
            let messages = self
              .state
              .commit::<N>(&mut self.blockchain, &self.signer, &mut txn, block, commit)
              .await;
            txn.commit();

            for message in messages {
              self.network.broadcast(message).await;
            }

            continue;
          }

          /*
            We do not have to interact with the database here as, on reboot, these timeouts will
            immediately expire and cause this behavior to occur once again (as this future has
            priority over incoming messages).
          */
          crate::or::Either::L(crate::or::Either::R(timeout)) => {
            let mut txn = self.db.txn();
            let messages = timeout.respond::<N>(&mut txn).await;
            txn.commit();

            for message in messages {
              self.network.broadcast(message).await;
            }
          }

          crate::or::Either::R(Ok(ref message)) => {
            // TODO: Remove this `Clone`
            let message = message.clone();
            drop(tick);

            let mut txn = self.db.txn();
            let validator = message.validator;
            match self.state.message::<N>(&self.blockchain, &self.signer, &mut txn, message).await {
              Ok(messages) => {
                txn.commit();
                for message in messages {
                  self.network.broadcast(message).await;
                }
              }
              Err(MessageError::Invalid(slash_reason)) => {
                self.blockchain.slash(validator, slash_reason);
                continue;
              }
              Err(
                MessageError::Stale |
                MessageError::Future |
                MessageError::NotValidator |
                MessageError::InvalidOuterSignature |
                MessageError::AlreadyHandled,
              ) => continue,
            }
          }
          // If our channels have been closed, terminate the consensus process
          crate::or::Either::L(crate::or::Either::L(Err(async_channel::RecvError))) |
          crate::or::Either::R(Err(async_channel::RecvError)) => return,
        }

        // Attempt to form a commit
        {
          let mut txn = self.db.txn();
          let messages =
            self.state.attempt_commit::<N>(&mut self.blockchain, &self.signer, &mut txn).await;
          txn.commit();

          for message in messages {
            self.network.broadcast(message).await;
          }
        }
      }
    }
  }

  /// The Tendermint process was terminated.
  ///
  /// This occurs when the future terminates, either due to being itself dropped or due to its
  /// handle being dropped.
  #[derive(Debug)]
  pub struct ProcessTerminated;

  impl Tendermint {
    async fn internal<
      B: Blockchain<
          Validator: BorshSerialize + BorshDeserialize,
          SignatureScheme: SignatureScheme<
            Signature: BorshSerialize + BorshDeserialize,
            AggregateSignature: BorshSerialize + BorshDeserialize,
          >,
          Block: BorshSerialize + BorshDeserialize + Block<Hash: BorshSerialize + BorshDeserialize>,
        >,
      S: Signer<
          Validator = B::Validator,
          Signature = <B::SignatureScheme as SignatureScheme>::Signature,
        >,
      D: Db,
      N: Network<
          B::Validator,
          <B::SignatureScheme as SignatureScheme>::Signature,
          <B::SignatureScheme as SignatureScheme>::AggregateSignature,
          B::Block,
        >,
    >(
      blockchain: B,
      signer: S,
      mut db: D,
      mut network: N,
      proposal: B::Block,
    ) -> (TendermintHandle<B>, TendermintProcess<B, S, D, N>) {
      // Sync blocks with a capacity of the amount of blocks per 5 minutes
      let (sync_send, sync_recv) = async_channel::bounded({
        use core::time::Duration;
        let time_per_block = N::BLOCK_DOWNLOADING_TIME
          .saturating_add(N::BLOCK_PROCESSING_TIME)
          .saturating_add(N::LATENCY_TIME.saturating_mul(3));
        let blocks_per_minute =
          Duration::from_mins(5).as_millis().div_ceil(time_per_block.as_millis().max(1));
        // Limit this to a sane range
        usize::try_from(blocks_per_minute).unwrap_or(usize::MAX).clamp(1, 64)
      });

      /*
        Limit the amount of messages proportionally to the amount of validators.

        So long as validators are honest and only send one message within a period, this bound
        will only be hit if either:
        1) Messages aren't drained faster than the network's declared latency time
        2) This validators is slower than the supermajority of validators
        where either cases are reasonable to establish the bound regarding.

        We do further scale the capacity by `2` to handle _some_ overages.
      */
      let (message_send, message_recv) =
        async_channel::bounded(2 * blockchain.validator_set().validators().into_iter().count());

      let mut txn = db.txn();
      let (state, messages) = State::new::<N>(&blockchain, &signer, &mut txn, proposal).await;
      txn.commit();

      for message in messages {
        network.broadcast(message).await;
      }

      (
        TendermintHandle {
          block_number: state.block_number_ref(),
          observed_block_number: state.observed_block_number_ref(),
          sync: sync_send,
          message: message_send,
        },
        (TendermintProcess {
          sync: sync_recv,
          message: message_recv,

          state,
          blockchain,
          signer,
          db,
          network,
        }),
      )
    }

    /// Initialize the Tendermint process.
    ///
    /// The returned future will run until its corresponding channels are closed. The future is NOT
    /// cancel-safe, and will have an undefined state in memory if cancelled. It MUST be polled
    /// until either:
    /// 1) It is of no further use, and accordingly its state may be undefined
    /// 2) The process terminates, so that the Tendermint process will be re-initialized from the
    ///    disk before any further use
    pub fn process<
      B: Send
        + Sync
        + Blockchain<
          Validator: Send + Sync + BorshSerialize + BorshDeserialize,
          ValidatorSet: Sync,
          SignatureScheme: SignatureScheme<
            Signature: Send + BorshSerialize + BorshDeserialize,
            AggregateSignature: Send + BorshSerialize + BorshDeserialize,
          >,
          Genesis: Sync,
          Block: Send
                   + Sync
                   + BorshSerialize
                   + BorshDeserialize
                   + Block<Hash: Send + BorshSerialize + BorshDeserialize>,
          BlockProposal: Send,
        >,
      S: Send
        + Sync
        + Signer<
          Validator = B::Validator,
          Signature = <B::SignatureScheme as SignatureScheme>::Signature,
          SignFuture: Send,
        >,
      D: Send + for<'db> Db<Transaction<'db>: Send>,
      N: Send
        + Network<
          B::Validator,
          <B::SignatureScheme as SignatureScheme>::Signature,
          <B::SignatureScheme as SignatureScheme>::AggregateSignature,
          B::Block,
          Sleep: Send,
        >,
    >(
      blockchain: B,
      signer: S,
      db: D,
      network: N,
      proposal: B::Block,
    ) -> impl Send + Future<Output = (TendermintHandle<B>, impl Send + Future<Output = ()>)> {
      async move {
        let (handle, process) = Self::internal(blockchain, signer, db, network, proposal).await;
        (handle, process.run())
      }
    }

    /// A variant of [`Tendermint::process`] which supports `!Send`, `!Sync` arguments.
    ///
    /// This is intended to enable support for single-threaded runtimes which do not require such
    /// bounds.
    #[expect(clippy::manual_async_fn)]
    pub fn process_single_threaded<
      B: Blockchain<
          Validator: BorshSerialize + BorshDeserialize,
          SignatureScheme: SignatureScheme<
            Signature: BorshSerialize + BorshDeserialize,
            AggregateSignature: BorshSerialize + BorshDeserialize,
          >,
          Block: BorshSerialize + BorshDeserialize + Block<Hash: BorshSerialize + BorshDeserialize>,
        >,
      S: Signer<
          Validator = B::Validator,
          Signature = <B::SignatureScheme as SignatureScheme>::Signature,
        >,
      D: Db,
      N: Network<
          B::Validator,
          <B::SignatureScheme as SignatureScheme>::Signature,
          <B::SignatureScheme as SignatureScheme>::AggregateSignature,
          B::Block,
        >,
    >(
      blockchain: B,
      signer: S,
      db: D,
      network: N,
      proposal: B::Block,
    ) -> impl Future<Output = (TendermintHandle<B>, impl Future<Output = ()>)> {
      async move {
        let (handle, process) = Self::internal(blockchain, signer, db, network, proposal).await;
        (handle, process.run())
      }
    }
  }

  impl<B: Blockchain> TendermintHandle<B> {
    /// The number for the block we're currently attempting to achieve consensus over.
    ///
    /// This is implemented in a lock-free manner and MAY momentarily desynchronize from the block
    /// number internal to the Tendermint process, or the blockchain, accordingly.
    pub fn block_number(&self) -> BlockNumber {
      BlockNumber(
        NonZero::new(self.block_number.load(Ordering::Acquire))
          .expect("block number was corrupted"),
      )
    }

    /// The greatest block number we've observed validators attempting to achieve consensus over.
    ///
    /// This is the greatest block number which `f + 1` validators have been observed to be
    /// attempting to obtain consensus over, meaning there presumably is consensus over all prior
    /// blocks (or the amount of faulty validators exceeds the fault threshold). This is intended
    /// to be used to allow the larger application to realize it should explicitly sync up to this
    /// block (as this library does not implement a block sync loop itself).
    ///
    /// This is implemented in a lock-free manner and MAY momentarily desynchronize from other
    /// representations of the state accordingly. A best-effort attempt is made to ensure this will
    /// always be greater than or equal to the value yielded by [`TendermintHandle::block_number`]
    /// but this is not guaranteed.
    pub fn observed_block_number(&self) -> BlockNumber {
      BlockNumber(
        NonZero::new(self.observed_block_number.load(Ordering::Acquire))
          .expect("observed block number was corrupted"),
      )
    }

    /// Sync a block by its commit.
    ///
    /// The Tendermint implementation will validate the commit as necessary.
    ///
    /// This function returns `Ok(())` if the Tendermint process is still running and `Err(())`
    /// otherwise. This function implements backpressure and will wait until the process has the
    /// capacity to receive this.
    pub async fn sync(
      &mut self,
      block: B::Block,
      commit: CommitFor<B>,
    ) -> Result<(), ProcessTerminated> {
      self.sync.send((block, commit)).await.map_err(|_| ProcessTerminated)
    }

    /// Handle a message received from the network.
    ///
    /// The Tendermint implementation will validate the message as necessary.
    ///
    /// This function returns `Ok(())` if the Tendermint process is still running and `Err(())`
    /// otherwise. This function implements backpressure and will wait until the process has the
    /// capacity to receive this.
    pub async fn message(&mut self, message: MessageFor<B>) -> Result<(), ProcessTerminated> {
      self.message.send(message).await.map_err(|_| ProcessTerminated)
    }
  }
}
#[cfg(feature = "std")]
pub use tendermint::*;
