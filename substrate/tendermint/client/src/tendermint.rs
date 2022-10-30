use std::{
  marker::PhantomData,
  sync::{Arc, RwLock},
  time::{UNIX_EPOCH, SystemTime, Duration},
};

use async_trait::async_trait;

use log::warn;

use tokio::sync::RwLock as AsyncRwLock;

use sp_core::{Encode, Decode, sr25519::Signature};
use sp_inherents::{InherentData, InherentDataProvider, CreateInherentDataProviders};
use sp_runtime::{
  traits::{Header, Block},
  Digest, Justification,
};
use sp_blockchain::HeaderBackend;
use sp_api::BlockId;

use sp_consensus::{Error, BlockOrigin, Proposer, Environment};
use sc_consensus::{ForkChoiceStrategy, BlockImportParams, import_queue::IncomingBlock};

use sc_service::ImportQueue;
use sc_client_api::{BlockBackend, Finalizer};

use tendermint_machine::{
  ext::{BlockError, BlockNumber, Commit, Network},
  SignedMessage, TendermintMachine, TendermintHandle,
};

use crate::{
  CONSENSUS_ID,
  types::TendermintValidator,
  validators::TendermintValidators,
  import_queue::{ImportFuture, TendermintImportQueue},
  Announce,
};

pub(crate) struct TendermintImport<T: TendermintValidator> {
  _ta: PhantomData<T>,

  validators: Arc<TendermintValidators<T>>,

  importing_block: Arc<RwLock<Option<<T::Block as Block>::Hash>>>,
  pub(crate) machine: Arc<RwLock<Option<TendermintHandle<Self>>>>,

  pub(crate) client: Arc<T::Client>,
  announce: T::Announce,
  providers: Arc<T::CIDP>,

  env: Arc<AsyncRwLock<T::Environment>>,
  pub(crate) queue:
    Arc<AsyncRwLock<Option<TendermintImportQueue<T::Block, T::BackendTransaction>>>>,
}

pub struct TendermintAuthority<T: TendermintValidator>(pub(crate) TendermintImport<T>);
impl<T: TendermintValidator> TendermintAuthority<T> {
  pub async fn validate(mut self) {
    let info = self.0.client.info();

    // Header::Number: TryInto<u64> doesn't implement Debug and can't be unwrapped
    let last_number = match info.best_number.try_into() {
      Ok(best) => BlockNumber(best),
      Err(_) => panic!("BlockNumber exceeded u64"),
    };
    let last_time = Commit::<TendermintValidators<T>>::decode(
      &mut self
        .0
        .client
        .justifications(&BlockId::Hash(info.best_hash))
        .unwrap()
        .map(|justifications| justifications.get(CONSENSUS_ID).cloned().unwrap())
        .unwrap_or_default()
        .as_ref(),
    )
    .map(|commit| commit.end_time)
    // TODO: Genesis start time + BLOCK_TIME
    .unwrap_or_else(|_| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

    let proposal = self
      .0
      .get_proposal(&self.0.client.header(BlockId::Hash(info.best_hash)).unwrap().unwrap())
      .await;

    *self.0.machine.write().unwrap() = Some(TendermintMachine::new(
      self.0.clone(),
      // TODO
      0, // ValidatorId
      (last_number, last_time),
      proposal,
    ));
  }
}

impl<T: TendermintValidator> Clone for TendermintImport<T> {
  fn clone(&self) -> Self {
    TendermintImport {
      _ta: PhantomData,

      validators: self.validators.clone(),

      importing_block: self.importing_block.clone(),
      machine: self.machine.clone(),

      client: self.client.clone(),
      announce: self.announce.clone(),
      providers: self.providers.clone(),

      env: self.env.clone(),
      queue: self.queue.clone(),
    }
  }
}

impl<T: TendermintValidator> TendermintImport<T> {
  pub(crate) fn new(
    client: Arc<T::Client>,
    announce: T::Announce,
    providers: Arc<T::CIDP>,
    env: T::Environment,
  ) -> TendermintImport<T> {
    TendermintImport {
      _ta: PhantomData,

      validators: Arc::new(TendermintValidators::new(client.clone())),

      importing_block: Arc::new(RwLock::new(None)),
      machine: Arc::new(RwLock::new(None)),

      client,
      announce,
      providers,

      env: Arc::new(AsyncRwLock::new(env)),
      queue: Arc::new(AsyncRwLock::new(None)),
    }
  }

  async fn check_inherents(
    &self,
    block: T::Block,
    providers: <T::CIDP as CreateInherentDataProviders<T::Block, ()>>::InherentDataProviders,
  ) -> Result<(), Error> {
    // TODO
    Ok(())
  }

  // Ensure this is part of a sequential import
  pub(crate) fn verify_order(
    &self,
    parent: <T::Block as Block>::Hash,
    number: <<T::Block as Block>::Header as Header>::Number,
  ) -> Result<(), Error> {
    let info = self.client.info();
    if (info.best_hash != parent) || ((info.best_number + 1u16.into()) != number) {
      Err(Error::Other("non-sequential import".into()))?;
    }
    Ok(())
  }

  // Do not allow blocks from the traditional network to be broadcast
  // Only allow blocks from Tendermint
  // Tendermint's propose message could be rewritten as a seal OR Tendermint could produce blocks
  // which this checks the proposer slot for, and then tells the Tendermint machine
  // While those would be more seamless with Substrate, there's no actual benefit to doing so
  fn verify_origin(&self, hash: <T::Block as Block>::Hash) -> Result<(), Error> {
    if let Some(tm_hash) = *self.importing_block.read().unwrap() {
      if hash == tm_hash {
        return Ok(());
      }
    }
    Err(Error::Other("block created outside of tendermint".into()))
  }

  // Errors if the justification isn't valid
  pub(crate) fn verify_justification(
    &self,
    hash: <T::Block as Block>::Hash,
    justification: &Justification,
  ) -> Result<(), Error> {
    if justification.0 != CONSENSUS_ID {
      Err(Error::InvalidJustification)?;
    }

    let commit: Commit<TendermintValidators<T>> =
      Commit::decode(&mut justification.1.as_ref()).map_err(|_| Error::InvalidJustification)?;
    if !self.verify_commit(hash, &commit) {
      Err(Error::InvalidJustification)?;
    }
    Ok(())
  }

  // Verifies the justifications aren't malformed, not that the block is justified
  // Errors if justifications is neither empty nor a sinlge Tendermint justification
  // If the block does have a justification, finalized will be set to true
  fn verify_justifications<BT>(
    &self,
    block: &mut BlockImportParams<T::Block, BT>,
  ) -> Result<(), Error> {
    if !block.finalized {
      if let Some(justifications) = &block.justifications {
        let mut iter = justifications.iter();
        let next = iter.next();
        if next.is_none() || iter.next().is_some() {
          Err(Error::InvalidJustification)?;
        }
        self.verify_justification(block.header.hash(), next.unwrap())?;
        block.finalized = true;
      }
    }
    Ok(())
  }

  pub(crate) async fn check<BT>(
    &self,
    block: &mut BlockImportParams<T::Block, BT>,
  ) -> Result<(), Error> {
    if block.finalized {
      if block.fork_choice.is_none() {
        // Since we alw1ays set the fork choice, this means something else marked the block as
        // finalized, which shouldn't be possible. Ensuring nothing else is setting blocks as
        // finalized ensures our security
        panic!("block was finalized despite not setting the fork choice");
      }
      return Ok(());
    }

    // Set the block as a worse choice
    block.fork_choice = Some(ForkChoiceStrategy::Custom(false));

    self.verify_order(*block.header.parent_hash(), *block.header.number())?;
    self.verify_justifications(block)?;

    // If the block wasn't finalized, verify the origin and validity of its inherents
    if !block.finalized {
      self.verify_origin(block.header.hash())?;
      if let Some(body) = block.body.clone() {
        self
          .check_inherents(
            T::Block::new(block.header.clone(), body),
            self.providers.create_inherent_data_providers(*block.header.parent_hash(), ()).await?,
          )
          .await?;
      }
    }

    // Additionally check these fields are empty
    // They *should* be unused, so requiring their emptiness prevents malleability and ensures
    // nothing slips through
    if !block.post_digests.is_empty() {
      Err(Error::Other("post-digests included".into()))?;
    }
    if !block.auxiliary.is_empty() {
      Err(Error::Other("auxiliary included".into()))?;
    }

    Ok(())
  }

  pub(crate) async fn get_proposal(&mut self, header: &<T::Block as Block>::Header) -> T::Block {
    let inherent_data =
      match self.providers.create_inherent_data_providers(header.hash(), ()).await {
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
      .env
      .write()
      .await
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
}

#[async_trait]
impl<T: TendermintValidator> Network for TendermintImport<T> {
  type ValidatorId = u16;
  type SignatureScheme = TendermintValidators<T>;
  type Weights = TendermintValidators<T>;
  type Block = T::Block;

  const BLOCK_TIME: u32 = { (serai_runtime::MILLISECS_PER_BLOCK / 1000) as u32 };

  fn signature_scheme(&self) -> Arc<TendermintValidators<T>> {
    self.validators.clone()
  }

  fn weights(&self) -> Arc<TendermintValidators<T>> {
    self.validators.clone()
  }

  async fn broadcast(&mut self, msg: SignedMessage<u16, Self::Block, Signature>) {
    // TODO
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

    let mut queue_write = self.queue.write().await;
    *self.importing_block.write().unwrap() = Some(hash);

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
      let info = self.client.info();
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
    debug_assert!(self.verify_justification(hash, &justification).is_ok());

    self
      .client
      .finalize_block(BlockId::Hash(hash), Some(justification), true)
      .map_err(|_| Error::InvalidJustification)
      .unwrap();
    self.announce.announce(hash);

    self.get_proposal(block.header()).await
  }
}
