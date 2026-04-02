use core::str::FromStr as _;
use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore as _, OsRng};

use sp_blockchain::HeaderBackend as _;
use sp_consensus::BlockStatus;
use sp_api::ProvideRuntimeApi as _;

use serai_abi::{
  primitives::{address::*, network_id::*, validator_sets::*},
  Transaction, SubstrateBlock as Block,
};
use serai_runtime::SeraiApi as _;

use jsonrpsee::{types::params::Params, RpcModule};

use sc_client_api::BlockBackend as _;
use sc_transaction_pool_api::TransactionPool;
use sc_network::config::MultiaddrWithPeerId;

mod utils;
use utils::*;

mod blockchain;
mod validator_sets;
mod p2p_validators;

use crate::FullClient;

pub(crate) struct FullDeps<P> {
  pub(crate) bootnodes: Vec<MultiaddrWithPeerId>,
  pub(crate) client: Arc<FullClient>,
  pub(crate) pool: Arc<P>,
  pub(crate) authority_discovery: Option<sc_authority_discovery::Service>,
}

pub(crate) fn create_full<P: 'static + TransactionPool<Block = Block>>(
  deps: FullDeps<P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>> {
  let FullDeps { bootnodes, client, pool, authority_discovery } = deps;

  let mut root = RpcModule::new(());
  root.merge(blockchain::module(client.clone(), pool)?)?;
  root.merge(validator_sets::module(client.clone())?)?;
  if let Some(authority_discovery) = authority_discovery {
    root.merge(p2p_validators::module(&bootnodes, client, authority_discovery)?)?;
  }
  Ok(root)
}
