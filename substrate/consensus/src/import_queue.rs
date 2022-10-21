// The Tendermint machine will call add_block for any block which is committed to, regardless of
// validity. To determine validity, it expects a validate function, which Substrate doesn't
// directly offer, and an add function. In order to comply with Serai's modified view of inherent
// transactions, validate MUST check inherents, yet add_block must not.
//
// In order to acquire a validate function, any block proposed by a legitimate proposer is
// imported. This performs full validation and makes the block available as a tip. While this would
// be incredibly unsafe thanks to the unchecked inherents, it's defined as a tip with less work,
// despite being a child of some parent. This means it won't be moved to nor operated on by the
// node.
//
// When Tendermint completes, the block is finalized, setting it as the tip regardless of work.

use std::{
  marker::PhantomData,
  sync::{Arc, RwLock},
  collections::HashMap,
};

use async_trait::async_trait;

use tokio::sync::RwLock as AsyncRwLock;

use sp_core::Decode;
use sp_application_crypto::sr25519::Signature;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::{
  traits::{Header, Block},
  Justification,
};
use sp_blockchain::HeaderBackend;
use sp_api::{BlockId, TransactionFor, ProvideRuntimeApi};

use sp_consensus::{Error, CacheKeyId};
#[rustfmt::skip] // rustfmt doesn't know how to handle this line
use sc_consensus::{
  ForkChoiceStrategy,
  BlockCheckParams,
  BlockImportParams,
  ImportResult,
  BlockImport,
  JustificationImport,
  BasicQueue,
};

use sc_client_api::{Backend, Finalizer};

use substrate_prometheus_endpoint::Registry;

use tendermint_machine::{
  ext::{BlockError, Commit, Network},
  SignedMessage,
};

use crate::{signature_scheme::TendermintSigner, weights::TendermintWeights};

const CONSENSUS_ID: [u8; 4] = *b"tend";

struct TendermintImport<
  B: Block,
  Be: Backend<B> + 'static,
  C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
  I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
  CIDP: CreateInherentDataProviders<B, ()> + 'static,
> {
  _block: PhantomData<B>,
  _backend: PhantomData<Be>,

  importing_block: Arc<RwLock<Option<B::Hash>>>,

  client: Arc<C>,
  inner: Arc<AsyncRwLock<I>>,
  providers: Arc<CIDP>,
}

impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
  > Clone for TendermintImport<B, Be, C, I, CIDP>
{
  fn clone(&self) -> Self {
    TendermintImport {
      _block: PhantomData,
      _backend: PhantomData,

      importing_block: self.importing_block.clone(),

      client: self.client.clone(),
      inner: self.inner.clone(),
      providers: self.providers.clone(),
    }
  }
}

impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
  > TendermintImport<B, Be, C, I, CIDP>
{
  async fn check_inherents(
    &self,
    block: B,
    providers: CIDP::InherentDataProviders,
  ) -> Result<(), Error> {
    todo!()
  }

  // Ensure this is part of a sequential import
  fn verify_order(
    &self,
    parent: B::Hash,
    number: <B::Header as Header>::Number,
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
  fn verify_origin(&self, hash: B::Hash) -> Result<(), Error> {
    if let Some(tm_hash) = *self.importing_block.read().unwrap() {
      if hash == tm_hash {
        return Ok(());
      }
    }
    Err(Error::Other("block created outside of tendermint".into()))
  }

  // Errors if the justification isn't valid
  fn verify_justification(
    &self,
    hash: B::Hash,
    justification: &Justification,
  ) -> Result<(), Error> {
    if justification.0 != CONSENSUS_ID {
      Err(Error::InvalidJustification)?;
    }

    let commit: Commit<TendermintSigner> =
      Commit::decode(&mut justification.1.as_ref()).map_err(|_| Error::InvalidJustification)?;
    if !self.verify_commit(hash, &commit) {
      Err(Error::InvalidJustification)?;
    }
    Ok(())
  }

  // Verifies the justifications aren't malformed, not that the block is justified
  // Errors if justifications is neither empty nor a sinlge Tendermint justification
  // If the block does have a justification, finalized will be set to true
  fn verify_justifications<T>(&self, block: &mut BlockImportParams<B, T>) -> Result<(), Error> {
    if !block.finalized {
      if let Some(justifications) = &block.justifications {
        let mut iter = justifications.iter();
        let next = iter.next();
        if next.is_none() || iter.next().is_some() {
          Err(Error::InvalidJustification)?;
        }
        self.verify_justification(block.header.hash(), next.unwrap())?;

        block.finalized = true; // TODO: Is this setting valid?
      }
    }
    Ok(())
  }

  async fn check<T>(&self, block: &mut BlockImportParams<B, T>) -> Result<(), Error> {
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
            B::new(block.header.clone(), body),
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
}
