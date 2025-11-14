use sp_blockchain::{Error as BlockchainError, HeaderMetadata, HeaderBackend};
use sc_client_api::BlockBackend;

use serai_abi::{primitives::prelude::*, SubstrateBlock as Block};

pub(super) fn block_hash<
  C: HeaderMetadata<Block, Error = BlockchainError> + HeaderBackend<Block> + BlockBackend<Block>,
>(
  client: &C,
  params: &jsonrpsee::types::params::Params,
) -> Result<<Block as sp_runtime::traits::Block>::Hash, jsonrpsee::types::error::ErrorObjectOwned> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct BlockByHash {
    block: String,
  };
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct BlockByNumber {
    block: u64,
  };

  Ok(if let Ok(block_hash) = params.parse::<BlockByHash>() {
    let Some(block_hash) = hex::decode(&block_hash.block).ok().and_then(|bytes| {
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
    let Ok(block_number) = params.parse::<BlockByNumber>() else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -1,
        "requested block wasn't a valid hash nor number",
        Option::<()>::None,
      ));
    };
    let Ok(Some(block_hash)) = client.block_hash(block_number.block) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't find requested block's hash",
        Option::<()>::None,
      ));
    };
    block_hash
  })
}
