//! The mempool for a Tributary.
//!
//! This is distinguished into the mempool for provided transactions and the mempool for (un)signed
//! transactions, due to the difference in semantics between them.
//!
//! Both mempools are implemented with the same pattern.
//! - Transactions may be added into the mempool by a mutable reference.
//! - The mempool may be polled to respond to requests for block proposals and handle the addition
//!   of new blocks.
//!
//! This avoids requiring any locks over the mempool's state between the application layer and the
//! blockchain.

use core::{
  pin::Pin,
  task::{Poll, Context},
};
use alloc::{vec::Vec, collections::BTreeSet};

use serai_db::{Db, Get, Transaction as DbTxn};

use crate::transaction::{TransactionError, TransactionKind, Transaction};

serai_db::schema!(TributaryMempool {
  // The last block this mempool has handled.
  LastBlock: (genesis: [u8; 32]) -> [u8; 32],
});

serai_db::channel!(TributaryMempool {
  // Validators to censure.
  Censure: (genesis: [u8; 32]) -> [u8; 32],
});

/// An error within the mempool.
#[derive(Clone, Debug)]
pub enum MempoolError {
  /// The transaction was invalid.
  Invalid(TransactionError),
  /// The transaction was already present within the mempool or on-chain.
  AlreadyPresent,
  /// The transaction had a signer who wasn't a validator (or was a slashed validator).
  InvalidSigner,
  /// The transaction conflicts with a transaction already present within the mempool or on-chain.
  Conflict,
  /// The signer has too many pre-existing transactions in the mempool.
  RateLimit,
}

impl From<TransactionError> for MempoolError {
  fn from(error: TransactionError) -> MempoolError {
    MempoolError::Invalid(error)
  }
}

/// The mempool for provided transactions.
mod provided;
use provided::*;
pub(crate) use provided::ProvidedReader;

/// The mempool for (un)signed transactions.
mod un_signed;
use un_signed::*;

pin_project_lite::pin_project! {
  /// The mempool for a Tributary.
  ///
  /// This MUST be polled to respond to requests for block proposals.
  pub struct Mempool<D: Db, T: Transaction> {
    db: D,
    genesis: [u8; 32],

    last_block: [u8; 32],
    provided: Provided<T>,
    un_signed: UnSigned<T>,

    // The requests for block proposals.
    request: async_channel::Receiver<([u8; 32], async_channel::Sender<Vec<T>>)>,
    // A way to re-send requests for block proposals.
    //
    // `async_channel::Receiver` doesn't offer a `peek` function. If we aren't available to
    // service a request, we simply re-send the request message to handle it later, using the
    // channel itself as the buffer.
    resend_request: async_channel::WeakSender<([u8; 32], async_channel::Sender<Vec<T>>)>,
  }
}

impl<D: Db, T: Transaction> Future for Mempool<D, T> {
  type Output = ();
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let projection = self.project();

    // Index the blocks added on-chain
    if let Some(block) =
      crate::Reader::<T>::block_after(projection.db, *projection.genesis, *projection.last_block)
    {
      let block = crate::Reader::<T>::block(projection.db, *projection.genesis, block)
        .expect("block after last block wasn't saved to database");

      let mut txn = projection.db.txn();
      projection.provided.block(&mut txn, &block);
      projection.un_signed.block(&mut txn, &block);
      txn.commit();

      *projection.last_block = block.hash();

      // Yield after indexing a block
      return Poll::Pending;
    }

    // Handle censures
    {
      let mut txn = projection.db.txn();
      while let Some(validator) = Censure::try_recv(&mut txn, *projection.genesis) {
        projection.un_signed.censure(&mut txn, validator);
      }
      txn.commit();
    }

    // Receive requests for block proposals
    let Poll::Ready(Ok((parent, response))) = core::pin::pin!(projection.request.recv()).poll(cx)
    else {
      return Poll::Pending;
    };
    // If this proposal isn't building on our latest indexed block, re-queue the request
    if (parent != *projection.last_block) &&
      let Some(resend_request) = projection.resend_request.upgrade()
    {
      let _ = resend_request.try_send((parent, response));
      return Poll::Pending;
    }

    // Respond to a request for a block proposal with all transactions in our mempool
    let _ = response.try_send(
      projection
        .provided
        .block_proposal()
        .chain(projection.un_signed.block_proposal())
        .cloned()
        .collect::<Vec<_>>(),
    );

    Poll::Pending
  }
}

pub(crate) struct MempoolConsumer<T> {
  genesis: [u8; 32],
  censured: BTreeSet<[u8; 32]>,
  request: async_channel::Sender<([u8; 32], async_channel::Sender<Vec<T>>)>,
}

pub(crate) struct MempoolRecv<T>(Option<async_channel::Receiver<T>>);
impl<T> Future for MempoolRecv<Vec<T>> {
  type Output = Vec<T>;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let message = if let Some(ref receiver) = self.0 {
      let Poll::Ready(message) = core::pin::pin!(receiver.recv()).poll(cx) else {
        return Poll::Pending;
      };
      message.ok()
    } else {
      // If we don't have a receiver, it's because we couldn't send the request to the mempool
      None
    };
    // Fallback to an empty list of transactions
    Poll::Ready(message.unwrap_or_else(Vec::new))
  }
}

impl<T: Transaction> crate::tendermint::Mempool<T> for MempoolConsumer<T> {
  type Transactions = Vec<T>;
  type Future = MempoolRecv<Self::Transactions>;
  fn transactions(&mut self, parent_block: [u8; 32]) -> Self::Future {
    let (sender, receiver) = async_channel::bounded(1);
    /*
      We use `force_send`, replacing the existing message if there is one, as we only care for the
      next block's proposal.
    */
    let sent_request = self.request.force_send((parent_block, sender));
    MempoolRecv(sent_request.is_ok().then_some(receiver))
  }
  fn censured(&self, getter: &impl Get, validator: [u8; 32]) -> bool {
    self.censured.contains(&validator) || UnSigned::<T>::censured(getter, self.genesis, validator)
  }
  fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]) {
    if self.censured.insert(validator) {
      Censure::send(txn, self.genesis, &validator);
    }
  }
}

impl<D: Db, T: Transaction> Mempool<D, T> {
  pub(super) fn new(
    mut db: D,
    genesis: [u8; 32],
    validators: impl IntoIterator<Item = [u8; 32]>,
    rate_limit: usize,
  ) -> (Self, MempoolConsumer<T>) {
    let last_block = LastBlock::get(&db, genesis).unwrap_or(genesis);

    let provided = Provided::new(&db, genesis);

    let mut un_signed = {
      let mut txn = db.txn();
      let un_signed = UnSigned::new(&mut txn, genesis, validators, rate_limit);
      txn.commit();
      un_signed
    };

    {
      let mut txn = db.txn();
      while let Some(validator) = Censure::try_recv(&mut txn, genesis) {
        un_signed.censure(&mut txn, validator);
      }
      txn.commit();
    }

    let (request_send, request_recv) = async_channel::bounded(1);
    let resend_request = request_send.clone().downgrade();

    (
      Self { db, genesis, last_block, provided, un_signed, request: request_recv, resend_request },
      MempoolConsumer {
        genesis,

        /*
          This is a cache of validators which have been censured, yet this hasn't been reflected
          in the signed mempool's database yet. As we drained the `Censure` channel, ensuring all
          censures _have_ been incorporated into the `signed` mempool, we can leave this cache
          empty.
        */
        censured: BTreeSet::new(),

        request: request_send,
      },
    )
  }

  pub(crate) fn add(
    self: Pin<&mut Self>,
    txn: &mut impl DbTxn,
    transaction: T,
    bypass_rate_limit: bool,
  ) -> Result<(), MempoolError> {
    let projection = self.project();
    match transaction.kind() {
      TransactionKind::Provided { .. } => projection.provided.provide(txn, transaction),
      TransactionKind::Unsigned | TransactionKind::Signed { .. } => {
        projection.un_signed.add(txn, transaction, bypass_rate_limit)
      }
    }
  }
}
