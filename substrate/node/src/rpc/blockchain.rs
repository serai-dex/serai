use std::sync::Arc;

use sp_blockchain::{Error as BlockchainError, HeaderMetadata, HeaderBackend};
use sp_consensus::BlockStatus;
use sp_api::ProvideRuntimeApi;
use sc_client_api::BlockBackend;
use sc_transaction_pool_api::TransactionPool;

use serai_abi::{Transaction, SubstrateBlock as Block};

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
  pool: Arc<impl 'static + TransactionPool<Block = Block>>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("blockchain/latest_finalized_block_number", |_params, client, _ext| {
    client.info().finalized_number
  })?;

  module.register_method(
    "blockchain/is_finalized",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(&**client, &params)? else {
        return Ok(false);
      };
      let finalized = client.info().finalized_number;
      let Ok(Some(number)) = client.number(block_hash) else {
        return Ok(false);
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
    let Some(block_hash) = block_hash(&**client, &params)? else {
      return Ok(None);
    };
    let Ok(Some(block)) = client.block(block_hash) else {
      return Ok(None);
    };

    Ok(Some(hex::encode(borsh::to_vec(&serai_abi::Block::from(block.block)).unwrap())))
  })?;

  module.register_method("blockchain/events", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(&**client, &params)? else {
      Err(Error::InvalidStateReference)?
    };
    let Ok(events) = client.runtime_api().events(block_hash) else {
      Err(Error::InvalidStateReference)?
    };
    Ok(
      events
        .into_iter()
        .map(|events_per_tx| events_per_tx.into_iter().map(hex::encode).collect::<Vec<_>>())
        .collect::<Vec<_>>(),
    )
  })?;

  module.register_async_method("blockchain/publish_transaction", move |params, client, _ext| {
    let pool = pool.clone();
    async move {
      #[derive(sp_core::serde::Deserialize)]
      #[serde(crate = "sp_core::serde")]
      struct TransactionRequest {
        transaction: String,
      }
      let Ok(transaction) = params.parse::<TransactionRequest>() else {
        return Err(Error::InvalidRequest(r#"missing `string` "transaction" field"#));
      };
      let Ok(transaction) = hex::decode(transaction.transaction) else {
        Err(Error::InvalidRequest(r#"transaction was not hex-encoded"#))?
      };
      let Ok(transaction) =
        <Transaction as borsh::BorshDeserialize>::deserialize_reader(&mut transaction.as_slice())
      else {
        Err(Error::InvalidRequest(r#"transaction could not be deserialized"#))?
      };
      pool
        .submit_one(
          client.info().best_hash,
          sc_transaction_pool_api::TransactionSource::External,
          transaction,
        )
        .await
        .map_err(|e| Error::InvalidTransaction(format!("{e}")))?;
      Ok(())
    }
  })?;

  Ok(module)
}
