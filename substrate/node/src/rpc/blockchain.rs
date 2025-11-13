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

fn block_hash<
  C: HeaderMetadata<Block, Error = BlockchainError>
    + HeaderBackend<Block>
    + BlockBackend<Block>
    + ProvideRuntimeApi<Block>,
>(
  client: &C,
  params: &jsonrpsee::types::params::Params,
) -> Result<<Block as sp_runtime::traits::Block>::Hash, jsonrpsee::types::error::ErrorObjectOwned> {
  Ok(if let Ok(block_hash) = params.sequence().next::<String>() {
    let Some(block_hash) = hex::decode(&block_hash).ok().and_then(|bytes| {
      <[u8; 32]>::try_from(bytes.as_slice())
        .map(<Block as sp_runtime::traits::Block>::Hash::from)
        .ok()
    }) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -1,
        "requested block hash wasn't a valid hash",
        Option::<()>::None,
      ));
    };
    block_hash
  } else {
    let Ok(block_number) = params.sequence().next::<u64>() else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -1,
        "requested block wasn't a valid hash nor number",
        Option::<()>::None,
      ));
    };
    let Ok(Some(block_hash)) = client.block_hash(block_number) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't find requested block's hash",
        Option::<()>::None,
      ));
    };
    block_hash
  })
}

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

  module.register_method("serai_latestFinalizedBlockNumber", |_params, client, _ext| {
    client.info().finalized_number
  });

  module.register_method("serai_isFinalized", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let finalized = client.info().finalized_number;
    let Ok(Some(number)) = client.number(block_hash) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "failed to fetch block's number",
        Option::<()>::None,
      ));
    };
    let Ok(status) = client.block_status(block_hash) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -3,
        "failed to fetch block's status",
        Option::<()>::None,
      ));
    };
    Ok(
      matches!(status, BlockStatus::InChainWithState | BlockStatus::InChainPruned) &&
        (number <= finalized),
    )
  })?;

  module.register_method("serai_block", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let Ok(Some(block)) = client.block(block_hash) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't find requested block",
        Option::<()>::None,
      ));
    };

    Ok(hex::encode(borsh::to_vec(&serai_abi::Block::from(block.block)).unwrap()))
  })?;

  module.register_method("serai_events", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let Ok(events) = client.runtime_api().events(block_hash) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't fetch the events for the requested block",
        Option::<()>::None,
      ));
    };
    Ok(events.into_iter().map(hex::encode).collect::<Vec<String>>())
  })?;

  Ok(module)
}
