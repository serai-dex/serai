use std::{sync::Arc, collections::HashSet};

use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_runtime::{
  primitives::{NetworkId, SubstrateAmount, PublicKey},
  Nonce, Block, SeraiRuntimeApi,
};

use tokio::sync::RwLock;

use jsonrpsee::RpcModule;

pub use sc_rpc_api::DenyUnsafe;
use sc_transaction_pool_api::TransactionPool;

pub struct FullDeps<C, P> {
  pub client: Arc<C>,
  pub pool: Arc<P>,
  pub deny_unsafe: DenyUnsafe,
  pub authority_discovery: Option<sc_authority_discovery::Service>,
}

pub fn create_full<
  C: ProvideRuntimeApi<Block>
    + HeaderBackend<Block>
    + HeaderMetadata<Block, Error = BlockchainError>
    + Send
    + Sync
    + 'static,
  P: TransactionPool + 'static,
>(
  deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
  C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, PublicKey, Nonce>
    + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, SubstrateAmount>
    + SeraiRuntimeApi<Block>
    + BlockBuilder<Block>,
{
  use substrate_frame_rpc_system::{System, SystemApiServer};
  use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};

  let mut module = RpcModule::new(());
  let FullDeps { client, pool, deny_unsafe, authority_discovery } = deps;

  module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
  module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

  if let Some(authority_discovery) = authority_discovery {
    let mut authority_discovery_module = RpcModule::new((client, RwLock::new(authority_discovery)));
    authority_discovery_module.register_async_method(
      "p2p_validators",
      |params, context| async move {
        let network: NetworkId = params.parse()?;
        let (client, authority_discovery) = &*context;
        let latest_block = client.info().best_hash;

        let validators = client.runtime_api().validators(latest_block, network).map_err(|_| {
          jsonrpsee::core::Error::to_call_error(std::io::Error::other(format!(
            "couldn't get validators from the latest block, which is likely a fatal bug. {}",
            "please report this at https://github.com/serai-dex/serai",
          )))
        })?;
        let mut all_p2p_addresses = vec![];
        for validator in validators {
          let mut returned_addresses = authority_discovery
            .write()
            .await
            .get_addresses_by_authority_id(validator.into())
            .await
            .unwrap_or_else(HashSet::new)
            .into_iter();
          let start_len = all_p2p_addresses.len();
          // Only take up to three addresses
          // There should be one, there may be two if their IP address changed, and 3 should only
          // occur if they have multiple proxies/an IP address changing frequentlly/some issue
          // preventing consistent self-identification
          // It shouldn't be harmful to try three addresses, yet it likely would be to try 1000
          while let Some(address) =
            returned_addresses.next().filter(|_| (all_p2p_addresses.len() - start_len) < 3)
          {
            all_p2p_addresses.push(address);
          }
        }
        // TODO: Remove mdns in the coordinator for this
        Ok(all_p2p_addresses)
      },
    )?;
    module.merge(authority_discovery_module)?;
  }

  Ok(module)
}
