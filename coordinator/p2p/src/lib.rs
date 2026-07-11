#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::future::Future;
use std::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{network_id::ExternalNetworkId, validator_sets::ExternalValidatorSet};

use serai_db::Db;
use tributary_sdk::{ReadWrite as _, TransactionTrait, Tributary, TributaryReader};
use serai_cosign::{SignedCosign, Cosigning};

use tokio::sync::{mpsc, oneshot};

use serai_task::{Task, ContinuallyRan as _};

/// The heartbeat task, effecting sync of Tributaries
pub mod heartbeat;
use crate::heartbeat::HeartbeatTask;

/// A heartbeat for a Tributary.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug)]
pub struct Heartbeat {
  /// The Tributary this is the heartbeat of.
  pub set: ExternalValidatorSet,
  /// The hash of the latest block added to the Tributary.
  pub latest_block_hash: [u8; 32],
}

/// A tributary block and its commit.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TributaryBlockWithCommit {
  /// The serialized block.
  pub block: Vec<u8>,
  /// The serialized commit.
  pub commit: Vec<u8>,
}

/// A representation of a peer.
pub trait Peer<'a>: Send {
  /// Send a heartbeat to this peer.
  fn send_heartbeat(
    &self,
    heartbeat: Heartbeat,
  ) -> impl Send + Future<Output = Option<Vec<TributaryBlockWithCommit>>>;
}

/// The representation of the P2P network.
pub trait P2p:
  Send + Sync + Clone + tributary_sdk::P2p + serai_cosign::RequestNotableCosigns
{
  /// The representation of a peer.
  type Peer<'a>: Peer<'a>;

  /// Fetch the peers for this network.
  fn peers(&self, network: ExternalNetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>>;

  /// Broadcast a cosign.
  fn publish_cosign(&self, cosign: SignedCosign) -> impl Send + Future<Output = ()>;

  /// A cancel-safe future for the next heartbeat received over the P2P network.
  ///
  /// Yields the validator set its for, the latest block hash observed, and a channel to return the
  /// descending blocks. This channel MUST NOT and will not have its receiver dropped before a
  /// message is sent.
  fn heartbeat(
    &self,
  ) -> impl Send + Future<Output = (Heartbeat, oneshot::Sender<Vec<TributaryBlockWithCommit>>)>;

  /// A cancel-safe future for the next request for the notable cosigns of a gloabl session.
  ///
  /// Yields the global session the request is for and a channel to return the notable cosigns.
  /// This channel MUST NOT and will not have its receiver dropped before a message is sent.
  fn notable_cosigns_request(
    &self,
  ) -> impl Send + Future<Output = ([u8; 32], oneshot::Sender<Vec<SignedCosign>>)>;

  /// A cancel-safe future for the next message regarding a Tributary.
  ///
  /// Yields the message's Tributary's genesis block hash and the message.
  fn tributary_message(&self) -> impl Send + Future<Output = ([u8; 32], Vec<u8>)>;

  /// A cancel-safe future for the next cosign received.
  fn cosign(&self) -> impl Send + Future<Output = SignedCosign>;
}

fn handle_notable_cosigns_request<D: 'static + Send + Sync + Db>(
  db: &D,
  global_session: [u8; 32],
  channel: oneshot::Sender<Vec<SignedCosign>>,
) {
  let cosigns = Cosigning::<D>::notable_or_latest_cosigns(db, global_session);
  channel.send(cosigns).expect("channel listening for cosign oneshot response was dropped?");
}

fn handle_heartbeat<D: 'static + Send + Sync + Db, T: TransactionTrait>(
  reader: &TributaryReader<D, T>,
  mut latest_block_hash: [u8; 32],
  channel: oneshot::Sender<Vec<TributaryBlockWithCommit>>,
) {
  let mut res_size = 8;
  let mut res = vec![];
  // This former case should be covered by this latter case
  while (res.len() < heartbeat::MIN_BLOCKS_PER_BATCH) || (res_size < heartbeat::BATCH_SIZE_LIMIT) {
    let Some(block_after) = reader.block_after(&latest_block_hash) else { break };

    // These `break` conditions should only occur under edge cases, such as if we're actively
    // deleting this Tributary due to being done with it
    let Some(block) = reader.block(&block_after) else { break };
    let block = block.serialize();
    let Some(commit) = reader.commit(&block_after) else { break };
    res_size += 8 + block.len() + 8 + commit.len();
    res.push(TributaryBlockWithCommit { block, commit });

    latest_block_hash = block_after;
  }
  channel
    .send(res)
    .map_err(|_| ())
    .expect("channel listening for heartbeat oneshot response was dropped?");
}

/// Run the P2P instance.
///
/// `add_tributary`'s and `retire_tributary's senders, along with `send_cosigns`'s receiver, must
/// never be dropped. `retire_tributary` is not required to only be instructed with added
/// Tributaries.
pub async fn run<TD: 'static + Send + Sync + Db, Tx: TransactionTrait, P: P2p>(
  db: impl 'static + Send + Sync + Db,
  p2p: P,
  mut add_tributary: mpsc::UnboundedReceiver<(ExternalValidatorSet, Tributary<TD, Tx, P>)>,
  mut retire_tributary: mpsc::UnboundedReceiver<ExternalValidatorSet>,
  send_cosigns: mpsc::UnboundedSender<SignedCosign>,
) {
  let mut readers = HashMap::<ExternalValidatorSet, TributaryReader<TD, Tx>>::new();
  let mut tributaries = HashMap::<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>::new();
  let mut heartbeat_tasks = HashMap::<ExternalValidatorSet, _>::new();

  loop {
    tokio::select! {
      tributary = add_tributary.recv() => {
        let (set, tributary) = tributary.expect("add_tributary send was dropped");
        let reader = tributary.reader();
        readers.insert(set, reader.clone());

        let (heartbeat_task_def, heartbeat_task) = Task::new();
        tokio::spawn(
          HeartbeatTask::new(set, tributary.clone(), reader.clone(), p2p.clone())
            .continually_run(heartbeat_task_def, vec![])
        );
        heartbeat_tasks.insert(set, heartbeat_task);

        let (tributary_message_send, mut tributary_message_recv) = mpsc::unbounded_channel();
        tributaries.insert(tributary.genesis(), tributary_message_send);
        // For as long as this sender exists, handle the messages from it on a dedicated task
        tokio::spawn(async move {
          while let Some(message) = tributary_message_recv.recv().await {
            tributary.handle_message(&message).await;
          }
        });
      }
      set = retire_tributary.recv() => {
        let set = set.expect("retire_tributary send was dropped");
        let Some(reader) = readers.remove(&set) else { continue };
        tributaries.remove(&reader.genesis()).expect("tributary reader but no tributary");
        heartbeat_tasks.remove(&set).expect("tributary but no heartbeat task");
      }

      (heartbeat, channel) = p2p.heartbeat() => {
        if let Some(reader) = readers.get(&heartbeat.set) {
          let reader = reader.clone(); // This is a cheap clone
          // We spawn this on a task due to the DB reads needed
          tokio::spawn(async move {
            handle_heartbeat(&reader, heartbeat.latest_block_hash, channel);
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
        if let Some(tributary) = tributaries.get(&tributary) {
          tributary.send(message).expect("tributary message recv was dropped?");
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
