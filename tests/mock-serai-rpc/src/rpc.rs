//! JSON-RPC method handlers mirroring the real Serai node.

use serai_abi::{
  primitives::{
    BlockHash,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, Session, ValidatorSet},
  },
};

use serde::Deserialize;
use jsonrpsee::{
  RpcModule,
  types::{error::ErrorObjectOwned, params::Params},
};

use crate::state::{SharedState, MockSeraiState};

/// Typed RPC errors mirroring `substrate/node/src/rpc/utils.rs`.
enum Error {
  Internal(String),
  InvalidRequest(String),
  InvalidStateReference,
  #[allow(dead_code)]
  InvalidTransaction(String),
}

impl From<Error> for ErrorObjectOwned {
  fn from(error: Error) -> Self {
    match error {
      Error::Internal(msg) => ErrorObjectOwned::owned(-1, msg, Option::<()>::None),
      Error::InvalidRequest(msg) => ErrorObjectOwned::owned(-2, msg, Option::<()>::None),
      Error::InvalidStateReference => ErrorObjectOwned::owned(
        -3,
        "the block used as the reference was not locally held",
        Option::<()>::None,
      ),
      Error::InvalidTransaction(msg) => ErrorObjectOwned::owned(
        -4,
        format!("transaction was not accepted to the mempool: {msg}"),
        Option::<()>::None,
      ),
    }
  }
}

/// Resolve a block hash from JSON-RPC params.
///
/// Mirrors `substrate/node/src/rpc/utils.rs`:
/// - `{ "block": "hex_hash" }` = lookup by hash
/// - `{ "block": 123 }` = lookup by number
fn resolve_block_hash(params: &Params, state: &MockSeraiState) -> Result<Option<BlockHash>, Error> {
  #[derive(Deserialize)]
  struct BlockByHash {
    block: String,
  }
  #[derive(Deserialize)]
  struct BlockByNumber {
    block: u64,
  }

  if let Ok(by_hash) = params.parse::<BlockByHash>() {
    let Some(hash_bytes) =
      hex::decode(&by_hash.block).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
      return Err(Error::InvalidRequest("requested block hash wasn't a valid hash".to_owned()));
    };
    let block_hash = BlockHash(hash_bytes);
    if state.block_number_by_hash.contains_key(&block_hash) {
      Ok(Some(block_hash))
    } else {
      Ok(None)
    }
  } else if let Ok(by_number) = params.parse::<BlockByNumber>() {
    Ok(state.block_hash_by_number(by_number.block))
  } else {
    Err(Error::InvalidRequest("requested block wasn't a valid hash nor number".to_owned()))
  }
}

fn network_from_str(network: &str) -> Result<NetworkId, Error> {
  Ok(match network.to_lowercase().as_str() {
    "serai" => NetworkId::Serai,
    "bitcoin" => NetworkId::External(ExternalNetworkId::Bitcoin),
    "ethereum" => NetworkId::External(ExternalNetworkId::Ethereum),
    "monero" => NetworkId::External(ExternalNetworkId::Monero),
    _ => return Err(Error::InvalidRequest("unrecognized network requested".to_owned())),
  })
}

fn parse_network(params: &Params) -> Result<NetworkId, Error> {
  #[derive(Deserialize)]
  struct Network {
    network: String,
  }
  let network: Network =
    params.parse().map_err(|_| Error::InvalidRequest(r#"missing "network" field"#.to_owned()))?;
  network_from_str(&network.network)
}

fn parse_set(params: &Params) -> Result<ExternalValidatorSet, Error> {
  #[derive(Deserialize)]
  struct Set {
    network: String,
    session: u32,
  }
  let set: Set = params
    .parse()
    .map_err(|_| Error::InvalidRequest(r#"missing "network"/"session" fields"#.to_owned()))?;
  let network = network_from_str(&set.network)?;
  ExternalValidatorSet::try_from(ValidatorSet { network, session: Session(set.session) }).map_err(
    |()| Error::InvalidRequest("requested keys for a non-external validator set".to_owned()),
  )
}

/// Build the RPC module with all method handlers matching the real Serai node.
pub fn build_rpc_module(state: SharedState) -> Result<RpcModule<SharedState>, ErrorObjectOwned> {
  let mut module = RpcModule::new(state);

  module
    .register_async_method(
      "blockchain/latest_finalized_block_number",
      async |_params, state, _ext| {
        let state = state.read().await;
        if let Some(err) =
          state.errors.check_random_failure("blockchain/latest_finalized_block_number")
        {
          return Err(Error::Internal(err));
        }
        if let Some(err) = state.errors.check_method("blockchain/latest_finalized_block_number") {
          return Err(Error::Internal(err.to_owned()));
        }
        Ok(state.latest_finalized_block_number().unwrap_or(0))
      },
    )
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("blockchain/is_finalized", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("blockchain/is_finalized") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("blockchain/is_finalized") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Ok(false);
      };
      if let Some(err) = state.errors.check_block_hash("blockchain/is_finalized", &block_hash) {
        return Err(Error::Internal(err.to_owned()));
      }
      Ok(state.block_number_by_hash.contains_key(&block_hash))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("blockchain/block", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("blockchain/block") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("blockchain/block") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Ok(None);
      };
      if let Some(err) = state.errors.check_block_hash("blockchain/block", &block_hash) {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(&number) = state.block_number_by_hash.get(&block_hash) else {
        return Ok(None);
      };
      if let Some(err) = state.errors.check_block_number("blockchain/block", number) {
        return Err(Error::Internal(err.to_owned()));
      }
      if state.missing_blocks.contains(&number) {
        return Ok(None);
      }
      let Some(block) = state.blocks_by_number.get(&number) else {
        return Ok(None);
      };
      Ok(Some(hex::encode(borsh::to_vec(block).unwrap())))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("blockchain/events", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("blockchain/events") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("blockchain/events") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      if let Some(err) = state.errors.check_block_hash("blockchain/events", &block_hash) {
        return Err(Error::Internal(err.to_owned()));
      }
      if let Some(&number) = state.block_number_by_hash.get(&block_hash) {
        if let Some(err) = state.errors.check_block_number("blockchain/events", number) {
          return Err(Error::Internal(err.to_owned()));
        }
      }
      let events = state.events_by_hash.get(&block_hash).cloned().unwrap_or_else(Vec::new);
      Ok(vec![events
        .into_iter()
        .map(|event| hex::encode(borsh::to_vec(&event).unwrap()))
        .collect::<Vec<String>>()])
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("validator-sets/current_session", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("validator-sets/current_session") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("validator-sets/current_session") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      let network = parse_network(&params)?;
      let vs = state.validator_sets_for_block(&block_hash);
      Ok(vs.sessions.get(&network).map(|s| s.0))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("validator-sets/current_stake", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("validator-sets/current_stake") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("validator-sets/current_stake") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      let network = parse_network(&params)?;
      let vs = state.validator_sets_for_block(&block_hash);
      Ok(vs.stakes.get(&network).map(|a| a.0))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("validator-sets/keys", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("validator-sets/keys") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("validator-sets/keys") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      let set = parse_set(&params)?;
      let vs = state.validator_sets_for_block(&block_hash);
      Ok(vs.keys.get(&set).map(|kp| hex::encode(borsh::to_vec(kp).unwrap())))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("validator-sets/current_validators", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("validator-sets/current_validators") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("validator-sets/current_validators") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      let network = parse_network(&params)?;
      let vs = state.validator_sets_for_block(&block_hash);
      Ok(vs.validators.get(&network).map(|v| v.iter().map(ToString::to_string).collect::<Vec<_>>()))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("validator-sets/pending_slash_report", async |params, state, _ext| {
      let state = state.read().await;
      if let Some(err) = state.errors.check_random_failure("validator-sets/pending_slash_report") {
        return Err(Error::Internal(err));
      }
      if let Some(err) = state.errors.check_method("validator-sets/pending_slash_report") {
        return Err(Error::Internal(err.to_owned()));
      }
      let Some(block_hash) = resolve_block_hash(&params, &state)? else {
        return Err(Error::InvalidStateReference);
      };
      let set = parse_set(&params)?;
      let vs = state.validator_sets_for_block(&block_hash);
      Ok(vs.pending_slash_reports.get(&set.network).copied().unwrap_or(true))
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  module
    .register_async_method("blockchain/publish_transaction", async |params, state, _ext| {
      {
        let state_read = state.read().await;
        if let Some(err) = state_read.errors.check_random_failure("blockchain/publish_transaction")
        {
          return Err(Error::Internal(err));
        }
        if let Some(err) = state_read.errors.check_method("blockchain/publish_transaction") {
          return Err(Error::Internal(err.clone()));
        }
      }
      #[derive(Deserialize)]
      struct Tx {
        transaction: String,
      }
      let tx: Tx = params
        .parse()
        .map_err(|_| Error::InvalidRequest(r#"missing "transaction" field"#.to_owned()))?;
      let tx_bytes = hex::decode(&tx.transaction)
        .map_err(|_| Error::InvalidRequest("transaction wasn't valid hex".to_owned()))?;
      state.write().await.published_transactions.push(tx_bytes);
      Ok(())
    })
    .map_err(|e| Error::Internal(e.to_string()))?;

  Ok(module)
}
