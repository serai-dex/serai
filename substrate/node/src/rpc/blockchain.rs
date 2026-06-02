use sc_transaction_pool_api::InPoolTransaction as _;

use serai_abi::system::{DispatchError, Event, TransactionStatus};

use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
  pool: Arc<impl 'static + TransactionPool<Block = Block, Hash = sp_core::H256>>,
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

  let pool_for_publish = pool.clone();
  module.register_async_method("blockchain/publish_transaction", move |params, client, _ext| {
    let pool = pool_for_publish.clone();
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

  module.register_async_method("blockchain/transaction_status", move |params, client, _ext| {
    let pool = pool.clone();
    async move {
      #[derive(sp_core::serde::Deserialize)]
      #[serde(crate = "sp_core::serde")]
      struct TxHash {
        tx: String,
      }

      // get tx hash
      let Ok(tx) = params.parse::<TxHash>() else {
        return Err(Error::InvalidRequest(r#"missing `string` "tx" field"#));
      };
      let tx_hash: [u8; 32] = hex::decode(&tx.tx)
        .map_err(|_| Error::InvalidRequest("invalid tx hash"))?
        .try_into()
        .map_err(|_| Error::InvalidRequest("invalid tx hash"))?;

      // get block
      let Some(block_hash) = block_hash(&client, &params)? else {
        return Err(Error::InvalidRequest(r#"missing `block` field in th request"#));
      };
      let Ok(Some(block)) = client.block(block_hash) else {
        return Err(Error::InvalidRequest("block not found"));
      };

      // first check the caller-supplied block; if the transaction is present, return its
      // dispatch outcome.
      for (index, tx) in serai_abi::Block::from(block.block).transactions.iter().enumerate() {
        if tx.hash() != tx_hash {
          continue;
        }

        // get block events
        let Ok(events) = client.runtime_api().events(block_hash) else {
          return Err(Error::InvalidStateReference);
        };
        // The runtime's `events()` output has a leading implicit bucket for the block-header
        // "transaction" deposited by `on_initialize`. User transactions therefore start at
        // index 1.
        let Some(bucket) = events.get(index + 1) else {
          return Err(Error::Internal("runtime returned no events bucket for transaction"));
        };

        // check per event
        let mut outcome: Option<Event> = None;
        for event_bytes in bucket {
          let Ok(event) = <serai_abi::Event as borsh::BorshDeserialize>::deserialize_reader(
            &mut event_bytes.as_slice(),
          ) else {
            continue;
          };

          match event {
            serai_abi::Event::System(e) => {
              outcome = Some(e);
              break;
            }
            serai_abi::Event::Coins(_) |
            serai_abi::Event::ValidatorSets(_) |
            serai_abi::Event::Signals(_) |
            serai_abi::Event::Dex(_) |
            serai_abi::Event::GenesisLiquidity(_) |
            serai_abi::Event::InInstructions(_) => {}
          }
        }
        let outcome = outcome.unwrap_or(Event::ExtrinsicFailed {
          error: DispatchError::Other(
            "runtime did not emit ExtrinsicSuccess/ExtrinsicFailed for transaction".into(),
          ),
        });

        return Ok(hex::encode(borsh::to_vec(&&TransactionStatus::Executed(outcome)).unwrap()));
      }

      // Not in the supplied block: consult the pool.
      let tx_hash: sp_core::H256 = tx_hash.into();
      let status = if pool.ready_transaction(&tx_hash).is_some() {
        TransactionStatus::InPool
      } else if pool.futures().iter().any(|fut| fut.hash() == &tx_hash) {
        TransactionStatus::Future
      } else {
        TransactionStatus::Dropped
      };
      Ok(hex::encode(borsh::to_vec(&status).unwrap()))
    }
  })?;

  Ok(module)
}
