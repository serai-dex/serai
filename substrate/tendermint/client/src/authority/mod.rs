use std::{
  sync::{Arc, RwLock},
  time::{UNIX_EPOCH, SystemTime, Duration},
  collections::HashSet,
};

use async_trait::async_trait;

use log::{debug, warn, error};

use futures::{
  SinkExt, StreamExt,
  lock::Mutex,
  channel::mpsc::{self, UnboundedSender},
};

use sp_core::{Encode, Decode, traits::SpawnEssentialNamed};
use sp_keystore::CryptoStore;
use sp_runtime::{
  traits::{Header, Block},
  Digest,
};
use sp_blockchain::HeaderBackend;

use sp_consensus::{Error, BlockOrigin, Proposer, Environment};
use sc_consensus::import_queue::IncomingBlock;

use sc_service::ImportQueue;
use sc_client_api::{BlockBackend, Finalizer, BlockchainEvents};
use sc_network::{ProtocolName, NetworkBlock};
use sc_network_gossip::GossipEngine;

use substrate_prometheus_endpoint::Registry;

use tendermint_machine::{
  ext::{BlockError, BlockNumber, Commit, SignatureScheme, Network},
  SignedMessage, TendermintMachine, TendermintHandle,
};

use crate::{
  CONSENSUS_ID, TendermintValidator,
  validators::{TendermintSigner, TendermintValidators},
  tendermint::TendermintImport,
};

mod gossip;
use gossip::TendermintGossip;

mod import_future;
use import_future::ImportFuture;

// Data for an active validator
// This is distinct as even when we aren't an authority, we still create stubbed Authority objects
// as it's only Authority which implements tendermint_machine::ext::Network. Network has
// verify_commit provided, and even non-authorities have to verify commits
struct ActiveAuthority<T: TendermintValidator> {
  signer: TendermintSigner<T>,

  // The number of the Block we're working on producing
  block_in_progress: Arc<RwLock<u64>>,
  // Notification channel for when we start on a new block
  new_block_event: UnboundedSender<()>,
  // Outgoing message queue, placed here as the GossipEngine itself can't be
  gossip: UnboundedSender<
    SignedMessage<u16, T::Block, <TendermintValidators<T> as SignatureScheme>::Signature>,
  >,

  // Block producer
  env: Arc<Mutex<T::Environment>>,
  announce: T::Network,
}

/// Tendermint Authority. Participates in the block proposal and voting process.
pub struct TendermintAuthority<T: TendermintValidator> {
  import: TendermintImport<T>,
  active: Option<ActiveAuthority<T>>,
}

// Get a block to propose after the specified header
// If stub is true, no time will be spent adding transactions to it (beyond what's required),
// making it as minimal as possible (a stub)
// This is so we can create proposals when syncing, respecting tendermint-machine's API boundaries,
// without spending the entire block processing time trying to include transactions (since we know
// our proposal is meaningless and we'll just be syncing a new block anyways)
async fn get_proposal<T: TendermintValidator>(
  env: &Arc<Mutex<T::Environment>>,
  import: &TendermintImport<T>,
  header: &<T::Block as Block>::Header,
  stub: bool,
) -> T::Block {
  let proposer =
    env.lock().await.init(header).await.expect("Failed to create a proposer for the new block");

  proposer
    .propose(
      import.inherent_data(*header.parent_hash()).await,
      Digest::default(),
      if stub {
        Duration::ZERO
      } else {
        // The first processing time is to build the block
        // The second is for it to be downloaded (assumes a block won't take longer to download
        // than it'll take to process)
        // The third is for it to actually be processed
        Duration::from_secs((T::BLOCK_PROCESSING_TIME_IN_SECONDS / 3).into())
      },
      Some(T::PROPOSED_BLOCK_SIZE_LIMIT),
    )
    .await
    .expect("Failed to crate a new block proposal")
    .block
}

impl<T: TendermintValidator> TendermintAuthority<T> {
  // Authority which is capable of verifying commits
  pub(crate) fn stub(import: TendermintImport<T>) -> Self {
    Self { import, active: None }
  }

  async fn get_proposal(&self, header: &<T::Block as Block>::Header) -> T::Block {
    get_proposal(&self.active.as_ref().unwrap().env, &self.import, header, false).await
  }

  /// Create and run a new Tendermint Authority, proposing and voting on blocks.
  /// This should be spawned on a task as it will not return until the P2P stack shuts down.
  #[allow(clippy::too_many_arguments, clippy::new_ret_no_self)]
  pub async fn new(
    genesis: SystemTime,
    protocol: ProtocolName,
    import: TendermintImport<T>,
    keys: Arc<dyn CryptoStore>,
    providers: T::CIDP,
    spawner: impl SpawnEssentialNamed,
    env: T::Environment,
    network: T::Network,
    registry: Option<&Registry>,
  ) {
    // This should only have a single value, yet a bounded channel with a capacity of 1 would cause
    // a firm bound. It's not worth having a backlog crash the node since we aren't constrained
    let (new_block_event_send, mut new_block_event_recv) = mpsc::unbounded();
    let (msg_send, mut msg_recv) = mpsc::unbounded();

    // Move the env into an Arc
    let env = Arc::new(Mutex::new(env));

    // Scoped so the temporary variables used here don't leak
    let (block_in_progress, mut gossip, TendermintHandle { mut step, mut messages, machine }) = {
      // Get the info necessary to spawn the machine
      let info = import.client.info();

      // Header::Number: TryInto<u64> doesn't implement Debug and can't be unwrapped
      let last_block: u64 = match info.finalized_number.try_into() {
        Ok(best) => best,
        Err(_) => panic!("BlockNumber exceeded u64"),
      };
      let last_hash = info.finalized_hash;

      let last_time = {
        // Convert into a Unix timestamp
        let genesis = genesis.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Get the last block's time by grabbing its commit and reading the time from that
        Commit::<TendermintValidators<T>>::decode(
          &mut import
            .client
            .justifications(last_hash)
            .unwrap()
            .map(|justifications| justifications.get(CONSENSUS_ID).cloned().unwrap())
            .unwrap_or_default()
            .as_ref(),
        )
        .map(|commit| commit.end_time)
        // The commit provides the time its block ended at
        // The genesis time is when the network starts
        // Accordingly, the end of the genesis block is a block time after the genesis time
        .unwrap_or_else(|_| genesis + u64::from(Self::block_time()))
      };

      let next_block = last_block + 1;
      // Shared references between us and the Tendermint machine (and its actions via its Network
      // trait)
      let block_in_progress = Arc::new(RwLock::new(next_block));

      // Write the providers into the import so it can verify inherents
      *import.providers.write().await = Some(providers);

      let authority = Self {
        import: import.clone(),
        active: Some(ActiveAuthority {
          signer: TendermintSigner(keys, import.validators.clone()),

          block_in_progress: block_in_progress.clone(),
          new_block_event: new_block_event_send,
          gossip: msg_send,

          env: env.clone(),
          announce: network.clone(),
        }),
      };

      // Get our first proposal
      let proposal = authority.get_proposal(&import.client.header(last_hash).unwrap().unwrap()).await;

      // Create the gossip network
      // This has to be spawning the machine, else gossip fails for some reason
      let gossip = GossipEngine::new(
        network,
        protocol,
        Arc::new(TendermintGossip::new(block_in_progress.clone(), import.validators.clone())),
        registry,
      );

      (
        block_in_progress,
        gossip,
        TendermintMachine::new(authority, BlockNumber(last_block), last_time, proposal).await,
      )
    };
    spawner.spawn_essential("machine", Some("tendermint"), Box::pin(machine.run()));

    // Start receiving messages about the Tendermint process for this block
    let mut gossip_recv =
      gossip.messages_for(TendermintGossip::<T>::topic(*block_in_progress.read().unwrap()));

    // Get finality events from Substrate
    let mut finality = import.client.finality_notification_stream();

    loop {
      futures::select_biased! {
        // GossipEngine closed down
        _ = gossip => {
          debug!(
            target: "tendermint",
            "GossipEngine shut down. {}",
            "Is the node shutting down?"
          );
          break;
        },

        // Synced a block from the network
        notif = finality.next() => {
          if let Some(notif) = notif {
            let number = match (*notif.header.number()).try_into() {
              Ok(number) => number,
              Err(_) => panic!("BlockNumber exceeded u64"),
            };

            // There's a race condition between the machine add_block and this
            // Both wait for a write lock on this ref and don't release it until after updating it
            // accordingly
            {
              let mut block_in_progress = block_in_progress.write().unwrap();
              if number < *block_in_progress {
                continue;
              }
              let next_block = number + 1;
              *block_in_progress = next_block;
              gossip_recv = gossip.messages_for(TendermintGossip::<T>::topic(next_block));
            }

            let justifications = import.client.justifications(notif.hash).unwrap().unwrap();
            step.send((
              BlockNumber(number),
              Commit::decode(&mut justifications.get(CONSENSUS_ID).unwrap().as_ref()).unwrap(),
              // This will fail if syncing occurs radically faster than machine stepping takes
              // TODO: Set true when initial syncing
              get_proposal(&env, &import, &notif.header, false).await
            )).await.unwrap();
          } else {
            debug!(
              target: "tendermint",
              "Finality notification stream closed down. {}",
              "Is the node shutting down?"
            );
            break;
          }
        },

        // Machine accomplished a new block
        new_block = new_block_event_recv.next() => {
          if new_block.is_some() {
            gossip_recv = gossip.messages_for(
              TendermintGossip::<T>::topic(*block_in_progress.read().unwrap())
            );
          } else {
            debug!(
              target: "tendermint",
              "Block notification stream shut down. {}",
              "Is the node shutting down?"
            );
            break;
          }
        },

        // Message to broadcast
        msg = msg_recv.next() => {
          if let Some(msg) = msg {
            let topic = TendermintGossip::<T>::topic(msg.block().0);
            gossip.gossip_message(topic, msg.encode(), false);
          } else {
            debug!(
              target: "tendermint",
              "Machine's message channel shut down. {}",
              "Is the node shutting down?"
            );
            break;
          }
        },

        // Received a message
        msg = gossip_recv.next() => {
          if let Some(msg) = msg {
            messages.send(
              match SignedMessage::decode(&mut msg.message.as_ref()) {
                Ok(msg) => msg,
                Err(e) => {
                  // This is guaranteed to be valid thanks to to the gossip validator, assuming
                  // that pipeline is correct. This doesn't panic as a hedge
                  error!(target: "tendermint", "Couldn't decode valid message: {}", e);
                  continue;
                }
              }
            ).await.unwrap();
          } else {
            debug!(
              target: "tendermint",
              "Gossip channel shut down. {}",
              "Is the node shutting down?"
            );
            break;
          }
        }
      }
    }
  }
}

#[async_trait]
impl<T: TendermintValidator> Network for TendermintAuthority<T> {
  type ValidatorId = u16;
  type SignatureScheme = TendermintValidators<T>;
  type Weights = TendermintValidators<T>;
  type Block = T::Block;

  const BLOCK_PROCESSING_TIME: u32 = T::BLOCK_PROCESSING_TIME_IN_SECONDS;
  const LATENCY_TIME: u32 = T::LATENCY_TIME_IN_SECONDS;

  fn signer(&self) -> TendermintSigner<T> {
    self.active.as_ref().unwrap().signer.clone()
  }

  fn signature_scheme(&self) -> TendermintValidators<T> {
    self.import.validators.clone()
  }

  fn weights(&self) -> TendermintValidators<T> {
    self.import.validators.clone()
  }

  async fn broadcast(
    &mut self,
    msg: SignedMessage<u16, Self::Block, <TendermintValidators<T> as SignatureScheme>::Signature>,
  ) {
    if self.active.as_mut().unwrap().gossip.unbounded_send(msg).is_err() {
      warn!(
        target: "tendermint",
        "Attempted to broadcast a message except the gossip channel is closed. {}",
        "Is the node shutting down?"
      );
    }
  }

  async fn slash(&mut self, validator: u16) {
    // TODO
    error!("slashing {}, if this is a local network, this shouldn't happen", validator);
  }

  // The Tendermint machine will call add_block for any block which is committed to, regardless of
  // validity. To determine validity, it expects a validate function, which Substrate doesn't
  // directly offer, and an add function. In order to comply with Serai's modified view of inherent
  // transactions, validate MUST check inherents, yet add_block must not.
  //
  // In order to acquire a validate function, any block proposed by a legitimate proposer is
  // imported. This performs full validation and makes the block available as a tip. While this
  // would be incredibly unsafe thanks to the unchecked inherents, it's defined as a tip with less
  // work, despite being a child of some parent. This means it won't be moved to nor operated on by
  // the node.
  //
  // When Tendermint completes, the block is finalized, setting it as the tip regardless of work.
  async fn validate(&mut self, block: &T::Block) -> Result<(), BlockError> {
    let hash = block.hash();
    let (header, body) = block.clone().deconstruct();
    let parent = *header.parent_hash();
    let number = *header.number();

    // Can happen when we sync a block while also acting as a validator
    if number <= self.import.client.info().best_number {
      debug!(target: "tendermint", "Machine proposed a block for a slot we've already synced");
      Err(BlockError::Temporal)?;
    }

    let mut queue_write = self.import.queue.write().await;
    *self.import.importing_block.write().unwrap() = Some(hash);

    queue_write.as_mut().unwrap().service_ref().import_blocks(
      BlockOrigin::ConsensusBroadcast, // TODO: Use BlockOrigin::Own when it's our block
      vec![IncomingBlock {
        hash,
        header: Some(header),
        body: Some(body),
        indexed_body: None,
        justifications: None,
        origin: None, // TODO
        allow_missing_state: false,
        skip_execution: false,
        import_existing: self.import.recheck.read().unwrap().contains(&hash),
        state: None,
      }],
    );

    ImportFuture::new(hash, queue_write.as_mut().unwrap()).await?;

    // Sanity checks that a child block can have less work than its parent
    {
      let info = self.import.client.info();
      assert_eq!(info.best_hash, parent);
      assert_eq!(info.finalized_hash, parent);
      assert_eq!(info.best_number, number - 1u8.into());
      assert_eq!(info.finalized_number, number - 1u8.into());
    }

    Ok(())
  }

  async fn add_block(
    &mut self,
    block: T::Block,
    commit: Commit<TendermintValidators<T>>,
  ) -> T::Block {
    // Prevent import_block from being called while we run
    let _lock = self.import.sync_lock.lock().await;

    // Check if we already imported this externally
    if self.import.client.justifications(block.hash()).unwrap().is_some() {
      debug!(target: "tendermint", "Machine produced a commit after we already synced it");
    } else {
      let hash = block.hash();
      let justification = (CONSENSUS_ID, commit.encode());
      debug_assert!(self.import.verify_justification(hash, &justification).is_ok());

      let raw_number = *block.header().number();
      let number: u64 = match raw_number.try_into() {
        Ok(number) => number,
        Err(_) => panic!("BlockNumber exceeded u64"),
      };

      let active = self.active.as_mut().unwrap();
      let mut block_in_progress = active.block_in_progress.write().unwrap();
      // This will hold true unless we received, and handled, a notification for the block before
      // its justification was made available
      debug_assert_eq!(number, *block_in_progress);

      // Finalize the block
      self
        .import
        .client
        .finalize_block(hash, Some(justification), true)
        .map_err(|_| Error::InvalidJustification)
        .unwrap();

      // Tell the loop we received a block and to move to the next
      *block_in_progress = number + 1;
      if active.new_block_event.unbounded_send(()).is_err() {
        warn!(
          target: "tendermint",
          "Attempted to send a new number to the gossip handler except it's closed. {}",
          "Is the node shutting down?"
        );
      }

      // Announce the block to the network so new clients can sync properly
      active.announce.announce_block(hash, None);
      active.announce.new_best_block_imported(hash, raw_number);
    }

    // Clear any blocks for the previous slot which we were willing to recheck
    *self.import.recheck.write().unwrap() = HashSet::new();

    self.get_proposal(block.header()).await
  }
}
