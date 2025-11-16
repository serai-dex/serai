use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderBackend};
use sp_api::ProvideRuntimeApi;

use serai_abi::{primitives::prelude::*, SubstrateBlock as Block};
use serai_runtime::SeraiApi;

use tokio::sync::RwLock;

use jsonrpsee::RpcModule;

use super::utils::Error;

pub(crate) fn module<
  C: 'static + Send + Sync + HeaderBackend<Block> + ProvideRuntimeApi<Block, Api: SeraiApi<Block>>,
>(
  id: String,
  client: Arc<C>,
  authority_discovery: sc_authority_discovery::Service,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new((id, client, RwLock::new(authority_discovery)));
  module.register_async_method("p2p_validators", |params, context, _ext| async move {
    let network = match params.parse::<[String; 1]>() {
      Ok([network]) => network,
      Err(e) => return Err(e),
    };

    let network = match network.to_lowercase().as_str() {
      "serai" => NetworkId::Serai,
      "bitcoin" => ExternalNetworkId::Bitcoin.into(),
      "ethereum" => ExternalNetworkId::Ethereum.into(),
      "monero" => ExternalNetworkId::Monero.into(),
      _ => Err(Error::InvalidRequest("network to fetch the `p2p_validators` of was unrecognized"))?,
    };
    let (id, client, authority_discovery) = &*context;
    let latest_block = client.info().best_hash;

    let validators = client
      .runtime_api()
      .validators(latest_block, network)
      .map_err(|_| Error::Internal("couldn't get validators from the latest block"));
    let validators = match validators {
      Ok(validators) => validators,
      Err(e) => Err(e)?,
    };
    // Always return the protocol's bootnodes
    let mut all_p2p_addresses = crate::chain_spec::bootnode_multiaddrs(id)
      .iter()
      .map(ToString::to_string)
      .collect::<Vec<_>>();
    // Additionally returns validators found over the DHT
    for validator in validators {
      let mut returned_addresses = authority_discovery
        .write()
        .await
        .get_addresses_by_authority_id(sp_core::sr25519::Public::from(validator).into())
        .await
        .unwrap_or_else(HashSet::new)
        .into_iter()
        .collect::<Vec<_>>();
      // Randomly select an address
      // There should be one, there may be two if their IP address changed, and more should only
      // occur if they have multiple proxies/an IP address changing frequently/some issue
      // preventing consistent self-identification
      // It isn't beneficial to use multiple addresses for a single peer here
      if !returned_addresses.is_empty() {
        all_p2p_addresses.push(
          libp2p::Multiaddr::from(
            returned_addresses
              .remove(usize::try_from(OsRng.next_u64() >> 32).unwrap() % returned_addresses.len()),
          )
          .to_string(),
        );
      }
    }
    Ok(all_p2p_addresses)
  })?;
  Ok(module)
}
