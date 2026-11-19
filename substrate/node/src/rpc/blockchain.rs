use sc_transaction_pool_api::InPoolTransaction as _;

use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
  pool: Arc<impl 'static + TransactionPool<Block = Block>>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("blockchain/latest_finalized_block_number", |_params, client, _ext| {
    client.info().finalized_number
  })?;

  module.register_method(
    "blockchain/is_finalized",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
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
    let Some(block_hash) = block_hash(client, &params)? else {
      return Ok(None);
    };
    let Ok(Some(block)) = client.block(block_hash) else {
      return Ok(None);
    };

    Ok(Some(hex::encode(borsh::to_vec(&serai_abi::Block::from(block.block)).unwrap())))
  })?;

  module.register_method("blockchain/events", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };
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

  let status_pool = pool.clone();
  module.register_method("blockchain/transaction_status", move |params, client, _ext| {
    use serai_abi::TransactionStatus;
    #[derive(sp_core::serde::Deserialize)]
    #[serde(crate = "sp_core::serde")]
    struct TxHash {
      tx: String,
    }

    // get tx hash
    let Ok(tx) = params.parse::<TxHash>() else {
      return Err(Error::InvalidRequest(r#"missing `string` "tx" field"#));
    };
    let Some(tx_hash) = hex::decode(&tx.tx).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
      Err(Error::InvalidRequest("requested transaction hash wasn't a valid hash"))?
    };

    // get block
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };
    let Ok(Some(block)) = client.block(block_hash) else {
      return Err(Error::InvalidStateReference);
    };

    // If the block included the transaction, yield its result from its events.
    if let Some(index) = serai_abi::Block::from(block.block)
      .transactions
      .iter()
      .position(|transaction| transaction.hash() == tx_hash)
    {
      let Ok(events) = client.runtime_api().events(block_hash) else {
        Err(Error::InvalidStateReference)?
      };

      // The first list of events is for the implicit transaction at the start of the block
      let Some(events) = events.get(index + 1) else {
        Err(Error::Internal("block didn't have the events for a transaction it included"))?
      };

      // The result is the final event of the transaction
      let result = events.iter().rev().find_map(|event| {
        if let Ok(serai_abi::Event::TransactionResult(result)) =
          borsh::from_slice::<serai_abi::Event>(event)
        {
          Some(result)
        } else {
          None
        }
      });
      let Some(result) = result else {
        Err(Error::Internal("transaction's events didn't include its result"))?
      };

      return Ok(hex::encode(borsh::to_vec(&TransactionStatus::Executed(result)).unwrap()));
    }

    // Not in the supplied block, consult the pool.
    let status = if status_pool.ready().any(|transaction| transaction.data().hash() == tx_hash) {
      TransactionStatus::InPool
    } else if status_pool.futures().iter().any(|transaction| transaction.data().hash() == tx_hash) {
      TransactionStatus::Future
    } else {
      TransactionStatus::Dropped
    };

    Ok(hex::encode(borsh::to_vec(&status).unwrap()))
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
