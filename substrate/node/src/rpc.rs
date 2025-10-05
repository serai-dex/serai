use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_runtime::{
  primitives::{NetworkId, SubstrateAmount, PublicKey},
  Nonce, Block, SeraiRuntimeApi,
};

use tokio::sync::RwLock;

use jsonrpsee::RpcModule;

use sc_client_api::BlockBackend;
use sc_transaction_pool_api::TransactionPool;

pub struct FullDeps<C, P> {
  pub id: String,
  pub client: Arc<C>,
  pub pool: Arc<P>,
  pub authority_discovery: Option<sc_authority_discovery::Service>,
}

pub fn create_full<
  C: ProvideRuntimeApi<Block>
    + HeaderBackend<Block>
    + HeaderMetadata<Block, Error = BlockchainError>
    + BlockBackend<Block>
    + Send
    + Sync
    + 'static,
  P: TransactionPool + 'static,
>(
  deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
  C::Api: frame_system_rpc_runtime_api::AccountNonceApi<Block, PublicKey, Nonce>
    + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, SubstrateAmount>
    + SeraiRuntimeApi<Block>
    + BlockBuilder<Block>,
{
  use substrate_frame_rpc_system::{System, SystemApiServer};
  use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};

  let mut module = RpcModule::new(());
  let FullDeps { id, client, pool, authority_discovery } = deps;

  module.merge(System::new(client.clone(), pool).into_rpc())?;
  module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

  if let Some(authority_discovery) = authority_discovery {
    let mut authority_discovery_module =
      RpcModule::new((id, client.clone(), RwLock::new(authority_discovery)));
    authority_discovery_module.register_async_method(
      "p2p_validators",
      |params, context, _ext| async move {
        let [network]: [NetworkId; 1] = params.parse()?;
        let (id, client, authority_discovery) = &*context;
        let latest_block = client.info().best_hash;

        let validators = client.runtime_api().validators(latest_block, network).map_err(|_| {
          jsonrpsee::types::error::ErrorObjectOwned::owned(
            -1,
            format!(
              "couldn't get validators from the latest block, which is likely a fatal bug. {}",
              "please report this at https://github.com/serai-dex/serai",
            ),
            Option::<()>::None,
          )
        });
        let validators = match validators {
          Ok(validators) => validators,
          Err(e) => return Err(e),
        };
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
              returned_addresses
                .remove(usize::try_from(OsRng.next_u64() >> 32).unwrap() % returned_addresses.len())
                .into(),
            );
          }
        }
        Ok(all_p2p_addresses)
      },
    )?;
    module.merge(authority_discovery_module)?;
  }

  let mut block_bin_module = RpcModule::new(client);
  block_bin_module.register_async_method(
    "chain_getBlockBin",
    |params, client, _ext| async move {
      let [block_hash]: [String; 1] = params.parse()?;
      let Some(block_hash) = hex::decode(&block_hash).ok().and_then(|bytes| {
        <[u8; 32]>::try_from(bytes.as_slice())
          .map(<Block as sp_runtime::traits::Block>::Hash::from)
          .ok()
      }) else {
        return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
          -1,
          "requested block hash wasn't a valid hash",
          Option::<()>::None,
        ));
      };
      let Some(block) = client.block(block_hash).ok().flatten() else {
        return Err(jsonrpsee::types::error::ErrorObjectOwned::owned(
          -1,
          "couldn't find requested block",
          Option::<()>::None,
        ));
      };
      Ok(hex::encode(block.block.encode()))
    },
  )?;
  module.merge(block_bin_module)?;

  Ok(module)
}
