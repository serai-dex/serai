use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderMetadata, HeaderBackend};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_abi::{primitives::prelude::*, SubstrateBlock as Block};
use serai_runtime::*;

use jsonrpsee::RpcModule;

use sc_client_api::BlockBackend;

pub(crate) fn module<
  C: 'static
    + Send
    + Sync
    + HeaderMetadata<Block, Error = BlockchainError>
    + HeaderBackend<Block>
    + BlockBackend<Block>
    + ProvideRuntimeApi<Block>,
>(
  client: Arc<C>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);
  module.register_async_method("serai_block", |params, client, _ext| async move {
    let [block_hash]: [String; 1] = params.parse()?;
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
    let Some(block) = client.block(block_hash).ok().flatten() else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't find requested block",
        Option::<()>::None,
      ));
    };
    Ok(hex::encode(block.block.encode()))
  })?;
  Ok(module)
}
