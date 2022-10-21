use std::{marker::PhantomData, sync::Arc, collections::HashMap};
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

use sp_core::Decode;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Header, Block};
use sp_blockchain::HeaderBackend;
use sp_api::{ProvideRuntimeApi, TransactionFor};

use sp_consensus::{Error, CacheKeyId};
#[rustfmt::skip]
use sc_consensus::{
  ForkChoiceStrategy,
  BlockCheckParams,
  BlockImportParams,
  ImportResult,
  BlockImport,
};

use tendermint_machine::ext::*;

use crate::signature_scheme::TendermintSigner;
const CONSENSUS_ID: [u8; 4] = *b"tend";

struct TendermintBlockImport<
  B: Block,
  C: Send + Sync + HeaderBackend<B> + ProvideRuntimeApi<B> + 'static,
  I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>>,
  CIDP: CreateInherentDataProviders<B, ()>,
> {
  _block: PhantomData<B>,
  client: Arc<C>,
  inner: I,
  providers: Arc<CIDP>,
}

impl<
    B: Block,
    C: Send + Sync + HeaderBackend<B> + ProvideRuntimeApi<B>,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>>,
    CIDP: CreateInherentDataProviders<B, ()>,
  > TendermintBlockImport<B, C, I, CIDP>
{
  async fn check_inherents(
    &self,
    block: B,
    providers: CIDP::InherentDataProviders,
  ) -> Result<(), Error> {
    todo!()
  }
}

#[async_trait::async_trait]
impl<
    B: Block,
    C: Send + Sync + HeaderBackend<B> + ProvideRuntimeApi<B>,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>>,
    CIDP: CreateInherentDataProviders<B, ()>,
  > BlockImport<B> for TendermintBlockImport<B, C, I, CIDP>
where
  I::Error: Into<Error>,
{
  type Error = Error;
  type Transaction = TransactionFor<C, B>;

  async fn check_block(
    &mut self,
    mut block: BlockCheckParams<B>,
  ) -> Result<ImportResult, Self::Error> {
    let info = self.client.info();
    if (info.best_hash != block.parent_hash) || ((info.best_number + 1u16.into()) != block.number) {
      Err(Error::Other("non-sequential import".into()))?;
    }

    block.allow_missing_state = false;
    block.allow_missing_parent = false;

    self.inner.check_block(block).await.map_err(Into::into)
  }

  async fn import_block(
    &mut self,
    mut block: BlockImportParams<B, Self::Transaction>,
    new_cache: HashMap<CacheKeyId, Vec<u8>>,
  ) -> Result<ImportResult, Self::Error> {
    if let Some(body) = block.body.clone() {
      if let Some(justifications) = block.justifications {
        let mut iter = justifications.iter();
        let next = iter.next();
        if next.is_none() || iter.next().is_some() {
          Err(Error::InvalidJustification)?;
        }
        let justification = next.unwrap();

        let commit: Commit<TendermintSigner> =
          Commit::decode(&mut justification.1.as_ref()).map_err(|_| Error::InvalidJustification)?;
        if justification.0 != CONSENSUS_ID {
          Err(Error::InvalidJustification)?;
        }

        // verify_commit
        todo!()
      } else {
        self
          .check_inherents(
            B::new(block.header.clone(), body),
            self.providers.create_inherent_data_providers(*block.header.parent_hash(), ()).await?,
          )
          .await?;
      }
    }

    if !block.post_digests.is_empty() {
      Err(Error::Other("post-digests included".into()))?;
    }
    if !block.auxiliary.is_empty() {
      Err(Error::Other("auxiliary included".into()))?;
    }

    block.fork_choice = Some(ForkChoiceStrategy::Custom(false));
    self.inner.import_block(block, new_cache).await.map_err(Into::into)
  }
}
