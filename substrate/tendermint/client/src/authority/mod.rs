use std::{
  sync::{Arc, RwLock},
  time::{UNIX_EPOCH, SystemTime, Duration},
  collections::HashSet,
};

use async_trait::async_trait;

use log::{warn, error};

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
use sp_api::BlockId;

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

  // Notification channel for when we start a new number
  new_number: Arc<RwLock<u64>>,
  new_number_event: UnboundedSender<()>,
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
  genesis: Option<u64>,
  import: TendermintImport<T>,
  active: Option<ActiveAuthority<T>>,
}

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
        // The first processing time is to build the block.
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
  /// Create a new TendermintAuthority.
  pub fn new(genesis: Option<SystemTime>, import: TendermintImport<T>) -> Self {
    Self {
      genesis: genesis.map(|genesis| {
        genesis.duration_since(UNIX_EPOCH).unwrap().as_secs() + u64::from(Self::block_time())
      }),
      import,
      active: None,
    }
  }

  fn get_last(&self) -> (<T::Block as Block>::Hash, (BlockNumber, u64)) {
    let info = self.import.client.info();

    (
      info.finalized_hash,
      (
        // Header::Number: TryInto<u64> doesn't implement Debug and can't be unwrapped
        match info.finalized_number.try_into() {
          Ok(best) => BlockNumber(best),
          Err(_) => panic!("BlockNumber exceeded u64"),
        },
        // Get the last time by grabbing the last block's justification and reading the time from
        // that
        Commit::<TendermintValidators<T>>::decode(
          &mut self
            .import
            .client
            .justifications(info.finalized_hash)
            .unwrap()
            .map(|justifications| justifications.get(CONSENSUS_ID).cloned().unwrap())
            .unwrap_or_default()
            .as_ref(),
        )
        .map(|commit| commit.end_time)
        .unwrap_or_else(|_| self.genesis.unwrap()),
      ),
    )
  }

  async fn get_proposal(&mut self, header: &<T::Block as Block>::Header) -> T::Block {
    get_proposal(&self.active.as_mut().unwrap().env, &self.import, header, false).await
  }

  /// Act as a network authority, proposing and voting on blocks. This should be spawned on a task
  /// as it will not return until the P2P stack shuts down.
  #[allow(clippy::too_many_arguments)]
  pub async fn authority(
    mut self,
    protocol: ProtocolName,
    keys: Arc<dyn CryptoStore>,
    providers: T::CIDP,
    spawner: impl SpawnEssentialNamed,
    env: T::Environment,
    network: T::Network,
    registry: Option<&Registry>,
  ) {
    let (best_hash, last) = self.get_last();
    let new_number = last.0 .0 + 1;

    // Shared references between us and the Tendermint machine (and its actions via its Network
    // trait)
    let number = Arc::new(RwLock::new(new_number));

    // Create the gossip network
    let mut gossip = GossipEngine::new(
      network.clone(),
      protocol,
      Arc::new(TendermintGossip::new(number.clone(), self.import.validators.clone())),
      registry,
    );

    // This should only have a single value, yet a bounded channel with a capacity of 1 would cause
    // a firm bound. It's not worth having a backlog crash the node since we aren't constrained
    let (new_number_send, mut new_number_recv) = mpsc::unbounded();
    let (gossip_send, mut gossip_recv) = mpsc::unbounded();

    // Clone the import object
    let import = self.import.clone();

    // Move the env into an Arc
    let env = Arc::new(Mutex::new(env));

    // Create the Tendermint machine
    let TendermintHandle { mut step, mut messages, machine } = {
      // Set this struct as active
      *self.import.providers.write().await = Some(providers);
      self.active = Some(ActiveAuthority {
        signer: TendermintSigner(keys, self.import.validators.clone()),

        new_number: number.clone(),
        new_number_event: new_number_send,
        gossip: gossip_send,

        env: env.clone(),
        announce: network,
      });

      let proposal = self
        .get_proposal(&self.import.client.header(BlockId::Hash(best_hash)).unwrap().unwrap())
        .await;

      // We no longer need self, so let TendermintMachine become its owner
      TendermintMachine::new(self, last, proposal).await
    };
    spawner.spawn_essential("machine", Some("tendermint"), Box::pin(machine.run()));

    // Start receiving messages about the Tendermint process for this block
    let mut recv = gossip.messages_for(TendermintGossip::<T>::topic(new_number));

    // Get finality events from Substrate
    let mut finality = import.client.finality_notification_stream();

    loop {
      futures::select_biased! {
        // GossipEngine closed down
        _ = gossip => break,

        // Synced a block from the network
        notif = finality.next() => {
          if let Some(notif) = notif {
            let this_number = match (*notif.header.number()).try_into() {
              Ok(number) => number,
              Err(_) => panic!("BlockNumber exceeded u64"),
            };

            // There's a race condition between the machine add_block and this
            // Both wait for a write lock on this number and don't release it until after updating
            // it accordingly
            {
              let mut number = number.write().unwrap();
              if this_number < *number {
                continue;
              }
              let new_number = this_number + 1;
              *number = new_number;
              recv = gossip.messages_for(TendermintGossip::<T>::topic(new_number));
            }

            let justifications = import.client.justifications(notif.hash).unwrap().unwrap();
            step.send((
              BlockNumber(this_number),
              Commit::decode(&mut justifications.get(CONSENSUS_ID).unwrap().as_ref()).unwrap(),
              // This will fail if syncing occurs radically faster than machine stepping takes
              // TODO: Set true when initial syncing
              get_proposal(&env, &import, &notif.header, false).await
            )).await.unwrap();
          } else {
            break;
          }
        },

        // Machine reached a new block
        new_number = new_number_recv.next() => {
          if new_number.is_some() {
            recv = gossip.messages_for(TendermintGossip::<T>::topic(*number.read().unwrap()));
          } else {
            break;
          }
        },

        // Message to broadcast
        msg = gossip_recv.next() => {
          if let Some(msg) = msg {
            let topic = TendermintGossip::<T>::topic(msg.block().0);
            gossip.gossip_message(topic, msg.encode(), false);
          } else {
            break;
          }
        },

        // Received a message
        msg = recv.next() => {
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
      Err(BlockError::Temporal)?;
    }

    let mut queue_write = self.import.queue.write().await;
    *self.import.importing_block.write().unwrap() = Some(hash);

    queue_write.as_mut().unwrap().import_blocks(
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
    let hash = block.hash();
    let justification = (CONSENSUS_ID, commit.encode());
    debug_assert!(self.import.verify_justification(hash, &justification).is_ok());

    let raw_number = *block.header().number();
    let this_number: u64 = match raw_number.try_into() {
      Ok(number) => number,
      Err(_) => panic!("BlockNumber exceeded u64"),
    };
    let new_number = this_number + 1;

    {
      let active = self.active.as_mut().unwrap();
      // Acquire the write lock
      let mut number = active.new_number.write().unwrap();

      // This block's number may not be the block we're working on if Substrate synced it before
      // the machine synced the necessary precommits
      if this_number == *number {
        // If we are the party responsible for handling this block, finalize it
        self
          .import
          .client
          .finalize_block(hash, Some(justification), true)
          .map_err(|_| Error::InvalidJustification)
          .unwrap();

        // Tell the loop there's a new number
        *number = new_number;
        if active.new_number_event.unbounded_send(()).is_err() {
          warn!(
            target: "tendermint",
            "Attempted to send a new number to the gossip handler except it's closed. {}",
            "Is the node shutting down?"
          );
        }
      }

      // Clear any blocks for the previous slot which we were willing to recheck
      *self.import.recheck.write().unwrap() = HashSet::new();

      // Announce the block to the network so new clients can sync properly
      active.announce.announce_block(hash, None);
      active.announce.new_best_block_imported(hash, raw_number);
    }

    self.get_proposal(block.header()).await
  }
}
