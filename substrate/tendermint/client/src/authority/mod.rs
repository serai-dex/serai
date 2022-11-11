use std::{
  sync::{Arc, RwLock},
  time::{UNIX_EPOCH, SystemTime, Duration},
  collections::HashSet,
};

use async_trait::async_trait;

use log::{warn, error};

use futures::{
  SinkExt, StreamExt,
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
use sc_client_api::{BlockBackend, Finalizer};
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
  new_number: UnboundedSender<u64>,
  // Outgoing message queue, placed here as the GossipEngine itself can't be
  gossip: UnboundedSender<
    SignedMessage<u16, T::Block, <TendermintValidators<T> as SignatureScheme>::Signature>,
  >,

  // Block producer
  env: T::Environment,
  announce: T::Network,
}

/// Tendermint Authority. Participates in the block proposal and voting process.
pub struct TendermintAuthority<T: TendermintValidator> {
  import: TendermintImport<T>,
  active: Option<ActiveAuthority<T>>,
}

impl<T: TendermintValidator> TendermintAuthority<T> {
  /// Create a new TendermintAuthority.
  pub fn new(import: TendermintImport<T>) -> Self {
    Self { import, active: None }
  }

  fn get_last(&self) -> (<T::Block as Block>::Hash, (BlockNumber, u64)) {
    let info = self.import.client.info();

    // TODO: Genesis start time + BLOCK_TIME
    let mut fake_genesis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Round up to the nearest 5s increment
    fake_genesis += 5 - (fake_genesis % 5);

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
        .unwrap_or(fake_genesis),
      ),
    )
  }

  pub(crate) async fn get_proposal(&mut self, header: &<T::Block as Block>::Header) -> T::Block {
    let parent = *header.parent_hash();

    let proposer = self
      .active
      .as_mut()
      .unwrap()
      .env
      .init(header)
      .await
      .expect("Failed to create a proposer for the new block");

    proposer
      .propose(
        self.import.inherent_data(parent).await,
        Digest::default(),
        // Assumes a block cannot take longer to download than it'll take to process
        Duration::from_secs((T::BLOCK_PROCESSING_TIME_IN_SECONDS / 2).into()),
        // TODO: Size limit
        None,
      )
      .await
      .expect("Failed to crate a new block proposal")
      .block
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
    let (new_number_tx, mut new_number_rx) = mpsc::unbounded();
    let (gossip_tx, mut gossip_rx) = mpsc::unbounded();

    // Create the Tendermint machine
    let TendermintHandle { mut messages, machine } = {
      // Set this struct as active
      *self.import.providers.write().await = Some(providers);
      self.active = Some(ActiveAuthority {
        signer: TendermintSigner(keys, self.import.validators.clone()),

        new_number: new_number_tx,
        gossip: gossip_tx,

        env,
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

    loop {
      futures::select_biased! {
        // GossipEngine closed down
        _ = gossip => break,

        // Machine reached a new height
        new_number = new_number_rx.next() => {
          if let Some(new_number) = new_number {
            *number.write().unwrap() = new_number;
            recv = gossip.messages_for(TendermintGossip::<T>::topic(new_number));
          } else {
            break;
          }
        },

        // Message to broadcast
        msg = gossip_rx.next() => {
          if let Some(msg) = msg {
            let topic = TendermintGossip::<T>::topic(msg.number().0);
            gossip.gossip_message(topic, msg.encode(), false);
          } else {
            break;
          }
        },

        // Received a message
        msg = recv.next() => {
          if let Some(msg) = msg {
            messages.send(match SignedMessage::decode(&mut msg.message.as_ref()) {
          Ok(msg) => msg,
          Err(e) => {
            // This is guaranteed to be valid thanks to to the gossip validator, assuming
              // that pipeline is correct. That's why this doesn't panic
              error!(target: "tendermint", "Couldn't decode valid message: {}", e);
              continue;
            }
          })
          .await
        .unwrap()
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

  async fn slash(&mut self, _validator: u16) {
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

    self
      .import
      .client
      .finalize_block(hash, Some(justification), true)
      .map_err(|_| Error::InvalidJustification)
      .unwrap();

    // Clear any blocks for the previous height we were willing to recheck
    *self.import.recheck.write().unwrap() = HashSet::new();

    let number: u64 = match (*block.header().number()).try_into() {
      Ok(number) => number,
      Err(_) => panic!("BlockNumber exceeded u64"),
    };
    if self.active.as_mut().unwrap().new_number.unbounded_send(number + 1).is_err() {
      warn!(
        target: "tendermint",
        "Attempted to send a new number to the gossip handler except it's closed. {}",
        "Is the node shutting down?"
      );
    }
    self.active.as_ref().unwrap().announce.announce_block(hash, None);

    self.get_proposal(block.header()).await
  }
}
