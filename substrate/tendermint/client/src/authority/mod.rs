use std::{
  sync::{Arc, RwLock},
  time::{UNIX_EPOCH, SystemTime, Duration},
};

use async_trait::async_trait;

use log::warn;

use tokio::task::yield_now;

use sp_core::{Encode, Decode, sr25519::Signature};
use sp_inherents::{InherentData, InherentDataProvider, CreateInherentDataProviders};
use sp_runtime::{
  traits::{Header, Block},
  Digest,
};
use sp_blockchain::HeaderBackend;
use sp_api::BlockId;

use sp_consensus::{Error, BlockOrigin, Proposer, Environment};
use sc_consensus::import_queue::IncomingBlock;

use sc_service::ImportQueue;
use sc_client_api::{BlockBackend, Finalizer};
use sc_network::NetworkBlock;
use sc_network_gossip::GossipEngine;

use substrate_prometheus_endpoint::Registry;

use tendermint_machine::{
  ext::{BlockError, BlockNumber, Commit, Network},
  SignedMessage, TendermintMachine,
};

use crate::{
  CONSENSUS_ID, TendermintValidator, validators::TendermintValidators, tendermint::TendermintImport,
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
  // Block whose gossip is being tracked
  number: Arc<RwLock<u64>>,
  // Outgoing message queue, placed here as the GossipEngine itself can't be
  gossip_queue: Arc<RwLock<Vec<SignedMessage<u16, T::Block, Signature>>>>,

  // Block producer
  env: T::Environment,
  announce: T::Network,
}

pub struct TendermintAuthority<T: TendermintValidator> {
  import: TendermintImport<T>,
  active: Option<ActiveAuthority<T>>,
}

impl<T: TendermintValidator> TendermintAuthority<T> {
  pub fn new(import: TendermintImport<T>) -> Self {
    Self { import, active: None }
  }

  fn get_last(&self) -> (<T::Block as Block>::Hash, (BlockNumber, u64)) {
    let info = self.import.client.info();

    (
      info.best_hash,
      (
        // Header::Number: TryInto<u64> doesn't implement Debug and can't be unwrapped
        match info.best_number.try_into() {
          Ok(best) => BlockNumber(best),
          Err(_) => panic!("BlockNumber exceeded u64"),
        },
        // Get the last time by grabbing the last block's justification and reading the time from
        // that
        Commit::<TendermintValidators<T>>::decode(
          &mut self
            .import
            .client
            .justifications(&BlockId::Hash(info.best_hash))
            .unwrap()
            .map(|justifications| justifications.get(CONSENSUS_ID).cloned().unwrap())
            .unwrap_or_default()
            .as_ref(),
        )
        .map(|commit| commit.end_time)
        // TODO: Genesis start time + BLOCK_TIME
        .unwrap_or_else(|_| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
      ),
    )
  }

  pub(crate) async fn get_proposal(&mut self, header: &<T::Block as Block>::Header) -> T::Block {
    let inherent_data = match self
      .import
      .providers
      .read()
      .await
      .as_ref()
      .unwrap()
      .create_inherent_data_providers(header.hash(), ())
      .await
    {
      Ok(providers) => match providers.create_inherent_data() {
        Ok(data) => Some(data),
        Err(err) => {
          warn!(target: "tendermint", "Failed to create inherent data: {}", err);
          None
        }
      },
      Err(err) => {
        warn!(target: "tendermint", "Failed to create inherent data providers: {}", err);
        None
      }
    }
    .unwrap_or_else(InherentData::new);

    let proposer = self
      .active
      .as_mut()
      .unwrap()
      .env
      .init(header)
      .await
      .expect("Failed to create a proposer for the new block");
    // TODO: Production time, size limit
    proposer
      .propose(inherent_data, Digest::default(), Duration::from_secs(1), None)
      .await
      .expect("Failed to crate a new block proposal")
      .block
  }

  /// Act as a network authority, proposing and voting on blocks. This should be spawned on a task
  /// as it will not return until the P2P stack shuts down.
  pub async fn authority(
    mut self,
    providers: T::CIDP,
    env: T::Environment,
    network: T::Network,
    registry: Option<&Registry>,
  ) {
    let (best_hash, last) = self.get_last();
    let mut last_number = last.0 .0 + 1;

    // Shared references between us and the Tendermint machine (and its actions via its Network
    // trait)
    let number = Arc::new(RwLock::new(last_number));
    let gossip_queue = Arc::new(RwLock::new(vec![]));

    // Create the gossip network
    let mut gossip = GossipEngine::new(
      network.clone(),
      "tendermint",
      Arc::new(TendermintGossip::new(number.clone(), self.import.validators.clone())),
      registry,
    );

    // Create the Tendermint machine
    let handle = {
      // Set this struct as active
      *self.import.providers.write().await = Some(providers);
      self.active = Some(ActiveAuthority {
        number: number.clone(),
        gossip_queue: gossip_queue.clone(),

        env,
        announce: network,
      });

      let proposal = self
        .get_proposal(&self.import.client.header(BlockId::Hash(best_hash)).unwrap().unwrap())
        .await;

      TendermintMachine::new(
        self, // We no longer need self, so let TendermintMachine become its owner
        0,    // TODO: ValidatorId
        last, proposal,
      )
    };

    // Start receiving messages about the Tendermint process for this block
    let mut recv = gossip
      .messages_for(TendermintGossip::<TendermintValidators<T>>::topic::<T::Block>(last_number));

    'outer: loop {
      // Send out any queued messages
      let mut queue = gossip_queue.write().unwrap().drain(..).collect::<Vec<_>>();
      for msg in queue.drain(..) {
        gossip.gossip_message(
          TendermintGossip::<TendermintValidators<T>>::topic::<T::Block>(msg.number().0),
          msg.encode(),
          false,
        );
      }

      // Handle any received messages
      // This inner loop enables handling all pending messages before  acquiring the out-queue lock
      // again
      'inner: loop {
        match recv.try_next() {
          Ok(Some(msg)) => handle
            .messages
            .send(match SignedMessage::decode(&mut msg.message.as_ref()) {
              Ok(msg) => msg,
              Err(e) => {
                warn!(target: "tendermint", "Couldn't decode valid message: {}", e);
                continue;
              }
            })
            .await
            .unwrap(),

          // Ok(None) IS NOT when there aren't messages available. It's when the channel is closed
          // If we're no longer receiving messages from the network, it must no longer be running
          // We should no longer be accordingly
          Ok(None) => break 'outer,

          // No messages available
          Err(_) => {
            // Check if we the block updated and should be listening on a different topic
            let curr = *number.read().unwrap();
            if last_number != curr {
              last_number = curr;
              // TODO: Will this return existing messages on the new height? Or will those have
              // been ignored and are now gone?
              recv = gossip.messages_for(TendermintGossip::<TendermintValidators<T>>::topic::<
                T::Block,
              >(last_number));
            }

            // If there are no messages available, yield to not hog the thread, then return to the
            // outer loop
            yield_now().await;
            break 'inner;
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

  const BLOCK_TIME: u32 = T::BLOCK_TIME_IN_SECONDS;

  fn signature_scheme(&self) -> Arc<TendermintValidators<T>> {
    self.import.validators.clone()
  }

  fn weights(&self) -> Arc<TendermintValidators<T>> {
    self.import.validators.clone()
  }

  async fn broadcast(&mut self, msg: SignedMessage<u16, Self::Block, Signature>) {
    self.active.as_mut().unwrap().gossip_queue.write().unwrap().push(msg);
  }

  async fn slash(&mut self, validator: u16) {
    todo!()
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

    let mut queue_write = self.import.queue.write().await;
    *self.import.importing_block.write().unwrap() = Some(hash);

    queue_write.as_mut().unwrap().import_blocks(
      // We do not want this block, which hasn't been confirmed, to be broadcast over the net
      // Substrate will generate notifications unless it's Genesis, which this isn't, InitialSync,
      // which changes telemtry behavior, or File, which is... close enough
      BlockOrigin::File,
      vec![IncomingBlock {
        hash,
        header: Some(header),
        body: Some(body),
        indexed_body: None,
        justifications: None,
        origin: None,
        allow_missing_state: false,
        skip_execution: false,
        // TODO: Only set to true if block was rejected due to its inherents
        import_existing: true,
        state: None,
      }],
    );

    if !ImportFuture::new(hash, queue_write.as_mut().unwrap()).await {
      todo!()
    }

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

    self
      .import
      .client
      .finalize_block(BlockId::Hash(hash), Some(justification), true)
      .map_err(|_| Error::InvalidJustification)
      .unwrap();
    *self.active.as_mut().unwrap().number.write().unwrap() += 1;
    self.active.as_ref().unwrap().announce.announce_block(hash, None);

    self.get_proposal(block.header()).await
  }
}
