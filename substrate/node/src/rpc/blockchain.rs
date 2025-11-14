use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderMetadata, HeaderBackend};
use sp_consensus::BlockStatus;
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;
use sc_client_api::BlockBackend;

use serai_abi::{primitives::prelude::*, SubstrateBlock as Block};

use serai_runtime::SeraiApi;

use jsonrpsee::RpcModule;

use super::utils::{Error, block_hash};

pub(crate) fn module<
  C: 'static
    + Send
    + Sync
    + HeaderMetadata<Block, Error = BlockchainError>
    + HeaderBackend<Block>
    + BlockBackend<Block>
    + ProvideRuntimeApi<Block, Api: SeraiApi<Block>>,
>(
  client: Arc<C>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("blockchain/latest_finalized_block_number", |_params, client, _ext| {
    client.info().finalized_number
  });

  module.register_method(
    "blockchain/is_finalized",
    |params, client, _ext| -> Result<_, Error> {
      let block_hash = block_hash(&**client, &params)?;
      let finalized = client.info().finalized_number;
      let Ok(Some(number)) = client.number(block_hash) else {
        Err(Error::Missing("failed to fetch block's number"))?
      };
      let Ok(status) = client.block_status(block_hash) else {
        Err(Error::Internal("failed to fetch block's status"))?
      };
      Ok(
        matches!(status, BlockStatus::InChainWithState | BlockStatus::InChainPruned) &&
          (number <= finalized),
      )
    },
  )?;

  module.register_method("blockchain/block", |params, client, _ext| -> Result<_, Error> {
    let block_hash = block_hash(&**client, &params)?;
    let Ok(Some(block)) = client.block(block_hash) else {
      Err(Error::Missing("couldn't find requested block"))?
    };

    Ok(hex::encode(borsh::to_vec(&serai_abi::Block::from(block.block)).unwrap()))
  })?;

  module.register_method("blockchain/events", |params, client, _ext| -> Result<_, Error> {
    let block_hash = block_hash(&**client, &params)?;
    let Ok(events) = client.runtime_api().events(block_hash) else {
      Err(Error::Missing("couldn't fetch the events for the requested block"))?
    };
    Ok(
      events
        .into_iter()
        .map(|events_per_tx| events_per_tx.into_iter().map(hex::encode).collect::<Vec<_>>())
        .collect::<Vec<_>>(),
    )
  })?;

  Ok(module)
}
