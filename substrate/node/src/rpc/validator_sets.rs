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

use super::utils::block_hash;

pub(super) fn network(
  params: &jsonrpsee::types::params::Params,
) -> Result<NetworkId, jsonrpsee::types::error::ErrorObjectOwned> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Network {
    network: String,
  }

  let Ok(network) = params.parse::<Network>() else {
    return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
      -1,
      r#"missing `string` "network" field"#,
      Option::<()>::None,
    ));
  };

  Ok(match network.network.to_lowercase().as_str() {
    "serai" => NetworkId::Serai,
    "bitcoin" => NetworkId::External(ExternalNetworkId::Bitcoin),
    "ethereum" => NetworkId::External(ExternalNetworkId::Ethereum),
    "monero" => NetworkId::External(ExternalNetworkId::Monero),
    _ => Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
      -1,
      "unrecognized network requested",
      Option::<()>::None,
    ))?,
  })
}

pub(super) fn set(
  params: &jsonrpsee::types::params::Params,
) -> Result<ValidatorSet, jsonrpsee::types::error::ErrorObjectOwned> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Set {
    network: String,
    session: u32,
  }

  let Ok(set) = params.parse::<Set>() else {
    return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
      -1,
      r#"missing `object` "set" field"#,
      Option::<()>::None,
    ));
  };

  let network = match set.network.to_lowercase().as_str() {
    "serai" => NetworkId::Serai,
    "bitcoin" => NetworkId::External(ExternalNetworkId::Bitcoin),
    "ethereum" => NetworkId::External(ExternalNetworkId::Ethereum),
    "monero" => NetworkId::External(ExternalNetworkId::Monero),
    _ => Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
      -1,
      "unrecognized network requested",
      Option::<()>::None,
    ))?,
  };

  Ok(ValidatorSet { network, session: Session(set.session) })
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
) -> RpcModule<impl 'static + Send + Sync> {
  let mut module = RpcModule::new(client);

  module.register_method("validator-sets/current_session", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let network = network(&params)?;
    let Ok(session) = client.runtime_api().current_session(block_hash, network) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't fetch the session for the requested network",
        Option::<()>::None,
      ));
    };
    Ok(session.map(|session| session.0))
  });

  module.register_method("validator-sets/current_stake", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let network = network(&params)?;
    let Ok(stake) = client.runtime_api().current_stake(block_hash, network) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't fetch the total allocated stake for the requested network",
        Option::<()>::None,
      ));
    };
    Ok(stake.map(|stake| stake.0))
  });

  module.register_method("validator-sets/keys", |params, client, _ext| {
    let block_hash = block_hash(&**client, &params)?;
    let set = set(&params)?;
    let Ok(set) = ExternalValidatorSet::try_from(set) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -1,
        "requested keys for a non-extenral validator set",
        Option::<()>::None,
      ));
    };
    let Ok(key_pair) = client.runtime_api().keys(block_hash, set) else {
      return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
        -2,
        "couldn't fetch the keys for the requested validator set",
        Option::<()>::None,
      ));
    };
    Ok(hex::encode(borsh::to_vec(&key_pair).unwrap()))
  });

  module
}
