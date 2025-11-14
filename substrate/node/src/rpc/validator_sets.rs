use std::{sync::Arc, ops::Deref, convert::AsRef, collections::HashSet};

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

fn network_from_str(network: impl AsRef<str>) -> Result<NetworkId, Error> {
  Ok(match network.as_ref().to_lowercase().as_str() {
    "serai" => NetworkId::Serai,
    "bitcoin" => NetworkId::External(ExternalNetworkId::Bitcoin),
    "ethereum" => NetworkId::External(ExternalNetworkId::Ethereum),
    "monero" => NetworkId::External(ExternalNetworkId::Monero),
    _ => Err(Error::InvalidRequest("unrecognized network requested"))?,
  })
}

pub(super) fn network(params: &jsonrpsee::types::params::Params) -> Result<NetworkId, Error> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Network {
    network: String,
  }

  let Ok(network) = params.parse::<Network>() else {
    Err(Error::InvalidRequest(r#"missing `string` "network" field"#))?
  };

  network_from_str(network.network)
}

pub(super) fn set(params: &jsonrpsee::types::params::Params) -> Result<ValidatorSet, Error> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Set {
    network: String,
    session: u32,
  }

  let Ok(set) = params.parse::<Set>() else {
    Err(Error::InvalidRequest(r#"missing `object` "set" field"#))?
  };

  Ok(ValidatorSet { network: network_from_str(set.network)?, session: Session(set.session) })
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

  module.register_method(
    "validator-sets/current_session",
    |params, client, _ext| -> Result<_, Error> {
      let block_hash = block_hash(&**client, &params)?;
      let network = network(&params)?;
      let Ok(session) = client.runtime_api().current_session(block_hash, network) else {
        Err(Error::Internal("couldn't fetch the session for the requested network"))?
      };
      Ok(session.map(|session| session.0))
    },
  );

  module.register_method(
    "validator-sets/current_stake",
    |params, client, _ext| -> Result<_, Error> {
      let block_hash = block_hash(&**client, &params)?;
      let network = network(&params)?;
      let Ok(stake) = client.runtime_api().current_stake(block_hash, network) else {
        Err(Error::Internal("couldn't fetch the total allocated stake for the requested network"))?
      };
      Ok(stake.map(|stake| stake.0))
    },
  );

  module.register_method("validator-sets/keys", |params, client, _ext| -> Result<_, Error> {
    let block_hash = block_hash(&**client, &params)?;
    let set = set(&params)?;
    let Ok(set) = ExternalValidatorSet::try_from(set) else {
      Err(Error::InvalidRequest("requested keys for a non-external validator set"))?
    };
    let Ok(key_pair) = client.runtime_api().keys(block_hash, set) else {
      Err(Error::Internal("couldn't fetch the keys for the requested validator set"))?
    };
    Ok(key_pair.map(|key_pair| hex::encode(borsh::to_vec(&key_pair).unwrap())))
  });

  module
}
