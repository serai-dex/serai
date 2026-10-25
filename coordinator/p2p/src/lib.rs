#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{network_id::ExternalNetworkId, validator_sets::ExternalValidatorSet};

use serai_db::Db;
use tributary_sdk::{
  ReadWriteAsBorsh, AggregateSignature,
  transaction::{TransactionKind, Transaction},
  mempool::MempoolNetwork,
  Block, Commit, Message, TributaryHandle,
};
use serai_cosign::{SignedCosign, Cosigning};

use tokio::sync::{mpsc, oneshot};

use serai_task::{Task, ContinuallyRan as _};

mod sync;
use crate::sync::SyncTask;

/// The batch size when responding to sync requests.
///
/// This is the batch's size _as scales the block size limit_. The actual batch may have more
/// blocks, the actual batch's size less than or equal to the size of this many theoretically
/// possible blocks.
pub const SYNC_BATCH_SIZE: usize = 10;
/// The `BLOCK_SIZE_LIMIT` used for sync batches when `T::BLOCK_SIZE_LIMIT = None`.
const SYNC_BATCH_FALLBACK_BLOCK_SIZE_LIMIT: usize = 1_024 * 1_024;

/// The size of a batch of synced blocks.
pub const fn sync_batch_size<Tx: Transaction>() -> usize {
  let block_size_limit = match Tx::BLOCK_SIZE_LIMIT {
    Some(block_size_limit) => block_size_limit,
    None => SYNC_BATCH_FALLBACK_BLOCK_SIZE_LIMIT,
  };
  SYNC_BATCH_SIZE.saturating_mul(block_size_limit)
}

/// A sync request for a Tributary.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug)]
pub struct SyncRequest {
  /// The Tributary this is a sync request for.
  pub set: ExternalValidatorSet,
  /// The hash of the latest block known on the Tributary.
  pub latest_block_hash: [u8; 32],
}

/// A tributary block and its commit.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct CommittedTributaryBlock<Tx: Transaction> {
  /// The serialized block.
  #[borsh(bound(serialize = "", deserialize = ""))]
  pub block: ReadWriteAsBorsh<Block<Tx>>,
  /// The serialized commit.
  pub commit: Commit,
}

/// A representation of a peer.
pub trait Peer<'p2p, Tx: Transaction>: Send {
  /// Send a sync request to this peer.
  fn send_sync_request(
    &self,
    sync_request: SyncRequest,
  ) -> impl Send + Future<Output = Option<Vec<CommittedTributaryBlock<Tx>>>>;
}

/// The representation of the P2P network.
pub trait P2p<Tx: Transaction>:
  Send
  + Sync
  + Clone
  + tendermint::Network<
    [u8; 32],
    [u8; 64],
    AggregateSignature,
    ReadWriteAsBorsh<Block<Tx>>,
    Sleep: Send,
  > + MempoolNetwork<Tx>
  + serai_cosign::RequestNotableCosigns
{
  /// The representation of a peer.
  type Peer<'p2p>: Peer<'p2p, Tx>;

  /// Fetch the peers for this network.
  fn peers(&self, network: ExternalNetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>>;

  /// Broadcast a cosign.
  fn publish_cosign(&self, cosign: SignedCosign) -> impl Send + Future<Output = ()>;

  /// A cancel-safe future for the next sync request received over the P2P network.
  ///
  /// This yields the sync request and a channel to respond with the descending blocks via.
  /// This channel MUST NOT and will not have its receiver dropped before a message is sent.
  fn sync_request(
    &self,
  ) -> impl Future<Output = (SyncRequest, oneshot::Sender<Vec<CommittedTributaryBlock<Tx>>>)>;

  /// A cancel-safe future for the next request for the notable cosigns of a gloabl session.
  ///
  /// This yields the global session the request is for and a channel to return the notable
  /// cosigns. This channel MUST NOT and will not have its receiver dropped before a message is
  /// sent.
  fn notable_cosigns_request(
    &self,
  ) -> impl Send + Future<Output = ([u8; 32], oneshot::Sender<Vec<SignedCosign>>)>;

  /// A cancel-safe future for the next message regarding a Tributary.
  ///
  /// This yields the message's Tributary's genesis and the message.
  fn tributary_message(&self) -> impl Send + Future<Output = ([u8; 32], Message<Tx>)>;

  /// A cancel-safe future for the next transaction gossiped for a Tributary.
  ///
  /// This yields the relevant Tributary's genesis and the transaction.
  fn tributary_transaction(&self) -> impl Send + Future<Output = ([u8; 32], Tx)>;

  /// A cancel-safe future for the next cosign received.
  fn cosign(&self) -> impl Send + Future<Output = SignedCosign>;
}

fn handle_notable_cosigns_request<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
>(
  db: &D,
  global_session: [u8; 32],
  channel: oneshot::Sender<Vec<SignedCosign>>,
) {
  let cosigns = Cosigning::<D>::notable_or_latest_cosigns(db, global_session);
  let _ = channel.send(cosigns);
}

fn handle_sync_request<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: Send + Sync + Transaction,
>(
  reader: &TributaryHandle<D, Tx>,
  mut latest_block_hash: [u8; 32],
  channel: oneshot::Sender<Vec<CommittedTributaryBlock<Tx>>>,
) {
  let mut res = Vec::with_capacity(1);
  if let Ok(mut res_size) = borsh::object_length(&res) {
    while let Some(block_after) = reader.block_after(latest_block_hash) {
      // These `break` conditions should only occur under edge cases, such as if we're actively
      // deleting this Tributary due to being done with it
      let Some(block) = reader.block(block_after) else { break };
      let Some(commit) = reader.commit(block_after) else { break };
      let committed_block = CommittedTributaryBlock { block: ReadWriteAsBorsh(block), commit };

      res_size = {
        let Ok(committed_block_size) = borsh::object_length(&committed_block) else { break };
        let Some(new_res_size) = res_size.checked_add(committed_block_size) else { break };
        if new_res_size > sync_batch_size::<Tx>() {
          break;
        }
        new_res_size
      };
      res.push(committed_block);

      latest_block_hash = block_after;
    }
  }
  let _ = channel.send(res);
}

/// Run the P2P instance.
///
/// `add_tributary`'s and `retire_tributary's senders, along with `send_cosigns`'s receiver, must
/// never be dropped. `retire_tributary` is not required to only be instructed with added
/// Tributaries.
pub async fn run<
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: 'static + Send + Sync + Transaction,
  P: P2p<Tx>,
>(
  db: impl 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  p2p: P,
  mut add_tributary: mpsc::UnboundedReceiver<(ExternalValidatorSet, TributaryHandle<TD, Tx>)>,
  mut retire_tributary: mpsc::UnboundedReceiver<ExternalValidatorSet>,
  send_cosigns: mpsc::UnboundedSender<SignedCosign>,
) {
  let mut readers = HashMap::<ExternalValidatorSet, TributaryHandle<TD, Tx>>::new();
  let mut tributary_messages = HashMap::<[u8; 32], mpsc::UnboundedSender<Message<Tx>>>::new();
  let mut tributary_transactions = HashMap::<[u8; 32], mpsc::UnboundedSender<Tx>>::new();
  let mut sync_request_tasks = HashMap::<ExternalValidatorSet, _>::new();

  loop {
    tokio::select! {
      tributary = add_tributary.recv() => {
        let (set, tributary) = tributary.expect("add_tributary send was dropped");
        let reader = tributary.clone();
        readers.insert(set, reader.clone());

        let (sync_request_task_def, sync_request_task) = Task::new();
        tokio::spawn(
          SyncTask::new(set, tributary.clone(), p2p.clone())
            .continually_run(sync_request_task_def, vec![])
        );
        sync_request_tasks.insert(set, sync_request_task);

        let (tributary_message_send, mut tributary_message_recv) = mpsc::unbounded_channel();
        tributary_messages.insert(tributary.genesis(), tributary_message_send);
        // For as long as this sender exists, handle the messages from it on a dedicated task
        tokio::spawn({
          let tributary = tributary.clone();
          async move {
            while let Some(message) = tributary_message_recv.recv().await {
              tributary.message(message).await;
            }
        }});

        let (tributary_transaction_send, mut tributary_transaction_recv) =
          mpsc::unbounded_channel();
        tributary_transactions.insert(tributary.genesis(), tributary_transaction_send);
        tokio::spawn(async move {
          while let Some(transaction) = tributary_transaction_recv.recv().await {
            if matches!(transaction.kind(), TransactionKind::Provided { .. }) {
              // TODO: Disconnect this peer
              continue;
            }
            // TODO: Handle this error, potentially disconnecting the peer?
            let _ = tributary.transaction(transaction).await;
          }
        });
      }
      set = retire_tributary.recv() => {
        let set = set.expect("retire_tributary send was dropped");
        let Some(reader) = readers.remove(&set) else { continue };
        tributary_messages
          .remove(&reader.genesis())
          .expect("tributary reader but no tributary message handler");
        tributary_transactions
          .remove(&reader.genesis())
          .expect("tributary reader but no tributary transaction handler");
        sync_request_tasks.remove(&set).expect("tributary but no sync request task");
      }

      (sync_request, channel) = p2p.sync_request() => {
        if let Some(reader) = readers.get(&sync_request.set) {
          let reader = reader.clone(); // This is a cheap clone
          // We spawn this on a task due to the DB reads needed
          // TODO: Ensure we have no more than one request per requester at a time
          tokio::spawn(async move {
            handle_sync_request(&reader, sync_request.latest_block_hash, channel);
          });
        }
      }
      (global_session, channel) = p2p.notable_cosigns_request() => {
        tokio::spawn({
          let db = db.clone();
          async move { handle_notable_cosigns_request(&db, global_session, channel) }
        });
      }
      (tributary, message) = p2p.tributary_message() => {
        if let Some(tributary) = tributary_messages.get(&tributary) {
          tributary.send(message).expect("tributary message recv was dropped?");
        }
      }
      (tributary, transaction) = p2p.tributary_transaction() => {
        if let Some(tributary) = tributary_transactions.get(&tributary) {
          tributary.send(transaction).expect("tributary transaction recv was dropped?");
        }
      }
      cosign = p2p.cosign() => {
        // We don't call `Cosigning::intake_cosign` here as that can only be called from a single
        // location. We also need to intake the cosigns we produce, which means we need to merge
        // these streams (signing, network) somehow. That's done with this mpsc channel
        send_cosigns.send(cosign).expect("channel receiving cosigns was dropped");
      }
    }
  }
}
