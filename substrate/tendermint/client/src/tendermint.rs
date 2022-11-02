use std::sync::{Arc, RwLock};

use log::warn;

use tokio::sync::RwLock as AsyncRwLock;

use sp_core::Decode;
use sp_runtime::{
  traits::{Header, Block},
  Justification,
};
use sp_inherents::{InherentData, InherentDataProvider, CreateInherentDataProviders};
use sp_blockchain::HeaderBackend;
use sp_api::{BlockId, ProvideRuntimeApi};

use sp_consensus::Error;
use sc_consensus::{ForkChoiceStrategy, BlockImportParams};

use sc_block_builder::BlockBuilderApi;

use tendermint_machine::ext::{BlockError, Commit, Network};

use crate::{
  CONSENSUS_ID, TendermintValidator, validators::TendermintValidators, TendermintImportQueue,
  authority::TendermintAuthority,
};

/// Tendermint import handler.
pub struct TendermintImport<T: TendermintValidator> {
  pub(crate) validators: Arc<TendermintValidators<T>>,

  pub(crate) providers: Arc<AsyncRwLock<Option<T::CIDP>>>,
  pub(crate) importing_block: Arc<RwLock<Option<<T::Block as Block>::Hash>>>,

  pub(crate) client: Arc<T::Client>,
  pub(crate) queue:
    Arc<AsyncRwLock<Option<TendermintImportQueue<T::Block, T::BackendTransaction>>>>,
}

impl<T: TendermintValidator> Clone for TendermintImport<T> {
  fn clone(&self) -> Self {
    TendermintImport {
      validators: self.validators.clone(),

      providers: self.providers.clone(),
      importing_block: self.importing_block.clone(),

      client: self.client.clone(),
      queue: self.queue.clone(),
    }
  }
}

impl<T: TendermintValidator> TendermintImport<T> {
  pub(crate) fn new(client: Arc<T::Client>) -> TendermintImport<T> {
    TendermintImport {
      validators: Arc::new(TendermintValidators::new(client.clone())),

      providers: Arc::new(AsyncRwLock::new(None)),
      importing_block: Arc::new(RwLock::new(None)),

      client,
      queue: Arc::new(AsyncRwLock::new(None)),
    }
  }

  pub(crate) async fn inherent_data(&self, parent: <T::Block as Block>::Hash) -> InherentData {
    match self
      .providers
      .read()
      .await
      .as_ref()
      .unwrap()
      .create_inherent_data_providers(parent, ())
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
    .unwrap_or_else(InherentData::new)
  }

  async fn check_inherents(&self, block: T::Block) -> Result<(), Error> {
    let inherent_data = self.inherent_data(*block.header().parent_hash()).await;
    let err = self
      .client
      .runtime_api()
      .check_inherents(&BlockId::Hash(self.client.info().finalized_hash), block, inherent_data)
      .map_err(|_| Error::Other(BlockError::Fatal.into()))?;

    if err.ok() {
      Ok(())
    } else if err.fatal_error() {
      Err(Error::Other(BlockError::Fatal.into()))
    } else {
      Err(Error::Other(BlockError::Temporal.into()))
    }
  }

  // Ensure this is part of a sequential import
  pub(crate) fn verify_order(
    &self,
    parent: <T::Block as Block>::Hash,
    number: <<T::Block as Block>::Header as Header>::Number,
  ) -> Result<(), Error> {
    let info = self.client.info();
    if (info.finalized_hash != parent) || ((info.finalized_number + 1u16.into()) != number) {
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
    if !TendermintAuthority::new(self.clone()).verify_commit(hash, &commit) {
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
    // Set the block as a worse choice
    block.fork_choice = Some(ForkChoiceStrategy::Custom(false));

    self.verify_order(*block.header.parent_hash(), *block.header.number())?;
    self.verify_justifications(block)?;

    // If the block wasn't finalized, verify the origin and validity of its inherents
    if !block.finalized {
      self.verify_origin(block.header.hash())?;
      if let Some(body) = block.body.clone() {
        self.check_inherents(T::Block::new(block.header.clone(), body)).await?;
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
}
