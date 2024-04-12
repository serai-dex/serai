use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore, OsRng};

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
  pub id: String,
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
  let FullDeps { id, client, pool, deny_unsafe, authority_discovery } = deps;

  module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
  module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

  if let Some(authority_discovery) = authority_discovery {
    let mut authority_discovery_module =
      RpcModule::new((id, client, RwLock::new(authority_discovery)));
    authority_discovery_module.register_async_method(
      "p2p_validators",
      |params, context| async move {
        let network: NetworkId = params.parse()?;
        let (id, client, authority_discovery) = &*context;
        let latest_block = client.info().best_hash;

        let validators = client.runtime_api().validators(latest_block, network).map_err(|_| {
          jsonrpsee::core::Error::to_call_error(std::io::Error::other(format!(
            "couldn't get validators from the latest block, which is likely a fatal bug. {}",
            "please report this at https://github.com/serai-dex/serai",
          )))
        })?;
        // Always return the protocol's bootnodes
        let mut all_p2p_addresses = crate::chain_spec::bootnode_multiaddrs(id);
        // Additionally returns validators found over the DHT
        for validator in validators {
          let mut returned_addresses = authority_discovery
            .write()
            .await
            .get_addresses_by_authority_id(validator.into())
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
              returned_addresses.remove(
                usize::try_from(OsRng.next_u64() >> 32).unwrap() % returned_addresses.len(),
              ),
            );
          }
        }
        Ok(all_p2p_addresses)
      },
    )?;
    module.merge(authority_discovery_module)?;
  }

  Ok(module)
}
