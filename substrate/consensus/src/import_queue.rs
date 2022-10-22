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
  time::Duration,
  collections::HashMap,
};

use async_trait::async_trait;

use log::warn;

use tokio::sync::RwLock as AsyncRwLock;

use sp_core::{Encode, Decode};
use sp_application_crypto::sr25519::Signature;
use sp_inherents::{InherentData, InherentDataProvider, CreateInherentDataProviders};
use sp_runtime::{
  traits::{Header, Block},
  Digest, Justification,
};
use sp_blockchain::HeaderBackend;
use sp_api::{BlockId, TransactionFor, ProvideRuntimeApi};

use sp_consensus::{Error, CacheKeyId, BlockOrigin, Proposer, Environment};
#[rustfmt::skip] // rustfmt doesn't know how to handle this line
use sc_consensus::{
  ForkChoiceStrategy,
  BlockCheckParams,
  BlockImportParams,
  Verifier,
  ImportResult,
  BlockImport,
  JustificationImport,
  import_queue::IncomingBlock,
  BasicQueue,
};

use sc_service::ImportQueue;
use sc_client_api::{Backend, Finalizer};

use substrate_prometheus_endpoint::Registry;

use tendermint_machine::{
  ext::{BlockError, Commit, Network},
  SignedMessage,
};

use crate::{signature_scheme::TendermintSigner, weights::TendermintWeights};

const CONSENSUS_ID: [u8; 4] = *b"tend";

pub type TendermintImportQueue<Block, Transaction> = BasicQueue<Block, Transaction>;

struct TendermintImport<
  B: Block,
  Be: Backend<B> + 'static,
  C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
  I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
  CIDP: CreateInherentDataProviders<B, ()> + 'static,
  E: Send + Sync + Environment<B> + 'static,
> {
  _block: PhantomData<B>,
  _backend: PhantomData<Be>,

  importing_block: Arc<RwLock<Option<B::Hash>>>,

  client: Arc<C>,
  inner: Arc<AsyncRwLock<I>>,
  providers: Arc<CIDP>,

  env: Arc<AsyncRwLock<E>>,
  queue: Arc<RwLock<Option<TendermintImportQueue<B, TransactionFor<C, B>>>>>,
}

impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > Clone for TendermintImport<B, Be, C, I, CIDP, E>
{
  fn clone(&self) -> Self {
    TendermintImport {
      _block: PhantomData,
      _backend: PhantomData,

      importing_block: self.importing_block.clone(),

      client: self.client.clone(),
      inner: self.inner.clone(),
      providers: self.providers.clone(),

      env: self.env.clone(),
      queue: self.queue.clone(),
    }
  }
}

impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  async fn check_inherents(
    &self,
    block: B,
    providers: CIDP::InherentDataProviders,
  ) -> Result<(), Error> {
    // TODO
    Ok(())
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

  async fn get_proposal(&mut self, block: &B) -> B {
    let inherent_data = match self.providers.create_inherent_data_providers(block.hash(), ()).await
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
      .env
      .write()
      .await
      .init(block.header())
      .await
      .expect("Failed to create a proposer for the new block");
    // TODO: Production time, size limit
    proposer
      .propose(inherent_data, Digest::default(), Duration::from_secs(1), None)
      .await
      .expect("Failed to crate a new block proposal")
      .block
  }

  fn import_justification_actual(
    &mut self,
    hash: B::Hash,
    justification: Justification,
  ) -> Result<(), Error> {
    self.verify_justification(hash, &justification)?;
    self
      .client
      .finalize_block(BlockId::Hash(hash), Some(justification), true)
      .map_err(|_| Error::InvalidJustification)
  }
}

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > BlockImport<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  I::Error: Into<Error>,
  TransactionFor<C, B>: Send + Sync + 'static,
{
  type Error = Error;
  type Transaction = TransactionFor<C, B>;

  // TODO: Is there a DoS where you send a block without justifications, causing it to error,
  // yet adding it to the blacklist in the process preventing further syncing?
  async fn check_block(
    &mut self,
    mut block: BlockCheckParams<B>,
  ) -> Result<ImportResult, Self::Error> {
    self.verify_order(block.parent_hash, block.number)?;

    // Does not verify origin here as origin only applies to unfinalized blocks
    // We don't have context on if this block has justifications or not

    block.allow_missing_state = false;
    block.allow_missing_parent = false;

    self.inner.write().await.check_block(block).await.map_err(Into::into)
  }

  async fn import_block(
    &mut self,
    mut block: BlockImportParams<B, TransactionFor<C, B>>,
    new_cache: HashMap<CacheKeyId, Vec<u8>>,
  ) -> Result<ImportResult, Self::Error> {
    self.check(&mut block).await?;
    self.inner.write().await.import_block(block, new_cache).await.map_err(Into::into)
  }
}

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > JustificationImport<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  type Error = Error;

  async fn on_start(&mut self) -> Vec<(B::Hash, <B::Header as Header>::Number)> {
    vec![]
  }

  async fn import_justification(
    &mut self,
    hash: B::Hash,
    _: <B::Header as Header>::Number,
    justification: Justification,
  ) -> Result<(), Error> {
    self.import_justification_actual(hash, justification)
  }
}

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > Verifier<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  async fn verify(
    &mut self,
    mut block: BlockImportParams<B, ()>,
  ) -> Result<(BlockImportParams<B, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
    self.check(&mut block).await.map_err(|e| format!("{}", e))?;
    Ok((block, None))
  }
}

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > Network for TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  type ValidatorId = u16;
  type SignatureScheme = TendermintSigner;
  type Weights = TendermintWeights;
  type Block = B;

  const BLOCK_TIME: u32 = { (serai_runtime::MILLISECS_PER_BLOCK / 1000) as u32 };

  fn signature_scheme(&self) -> Arc<TendermintSigner> {
    Arc::new(TendermintSigner::new())
  }

  fn weights(&self) -> Arc<TendermintWeights> {
    Arc::new(TendermintWeights)
  }

  async fn broadcast(&mut self, msg: SignedMessage<u16, Self::Block, Signature>) {
    // TODO
  }

  async fn slash(&mut self, validator: u16) {
    todo!()
  }

  fn validate(&mut self, block: &B) -> Result<(), BlockError> {
    let hash = block.hash();
    let (header, body) = block.clone().deconstruct();
    *self.importing_block.write().unwrap() = Some(hash);
    self.queue.write().unwrap().as_mut().unwrap().import_blocks(
      BlockOrigin::NetworkBroadcast,
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
    todo!()
    // self.queue.poll_actions
  }

  async fn add_block(&mut self, block: B, commit: Commit<TendermintSigner>) -> B {
    self.import_justification_actual(block.hash(), (CONSENSUS_ID, commit.encode())).unwrap();
    self.get_proposal(&block).await
  }
}

pub fn import_queue<
  B: Block,
  Be: Backend<B> + 'static,
  C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
  I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
  CIDP: CreateInherentDataProviders<B, ()> + 'static,
  E: Send + Sync + Environment<B> + 'static,
>(
  client: Arc<C>,
  inner: I,
  providers: Arc<CIDP>,
  env: E,
  spawner: &impl sp_core::traits::SpawnEssentialNamed,
  registry: Option<&Registry>,
) -> TendermintImportQueue<B, TransactionFor<C, B>>
where
  I::Error: Into<Error>,
  TransactionFor<C, B>: Send + Sync + 'static,
{
  let import = TendermintImport {
    _block: PhantomData,
    _backend: PhantomData,

    importing_block: Arc::new(RwLock::new(None)),

    client,
    inner: Arc::new(AsyncRwLock::new(inner)),
    providers,

    env: Arc::new(AsyncRwLock::new(env)),
    queue: Arc::new(RwLock::new(None)),
  };
  let boxed = Box::new(import.clone());

  let queue =
    || BasicQueue::new(import.clone(), boxed.clone(), Some(boxed.clone()), spawner, registry);
  *import.queue.write().unwrap() = Some(queue());
  queue()
}
