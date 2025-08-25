use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_runtime::{
  in_instructions::primitives::Shorthand,
  primitives::{ExternalNetworkId, NetworkId, PublicKey, SubstrateAmount, QuotePriceParams},
  validator_sets::ValidatorSetsApi,
  dex::DexApi,
  Block, Nonce,
};

use tokio::sync::RwLock;

use jsonrpsee::{RpcModule, core::Error};
use scale::Encode;

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
    + ValidatorSetsApi<Block>
    + DexApi<Block>
    + BlockBuilder<Block>,
{
  use substrate_frame_rpc_system::{System, SystemApiServer};
  use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
  use ciphersuite::Ciphersuite;
  use ciphersuite_kp256::{k256::elliptic_curve::point::AffineCoordinates, Secp256k1};
  use dalek_ff_group::Ed25519;
  use bitcoin_serai::bitcoin;

  let mut module = RpcModule::new(());
  let FullDeps { id, client, pool, deny_unsafe, authority_discovery } = deps;

  module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
  module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

  if let Some(authority_discovery) = authority_discovery {
    let mut authority_discovery_module =
      RpcModule::new((id, client.clone(), RwLock::new(authority_discovery)));
    authority_discovery_module.register_async_method(
      "p2p_validators",
      |params, context| async move {
        let network: NetworkId = params.parse()?;
        let (id, client, authority_discovery) = &*context;
        let latest_block = client.info().best_hash;

        let validators = client.runtime_api().validators(latest_block, network).map_err(|_| {
          Error::to_call_error(std::io::Error::other(format!(
            "couldn't get validators from the latest block, which is likely a fatal bug. {}",
            "please report this at https://github.com/serai-dex/serai/issues",
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

  let mut serai_json_module = RpcModule::new(client);

  // add network address rpc
  serai_json_module.register_async_method(
    "external_network_address",
    |params, context| async move {
      let network: ExternalNetworkId = params.parse()?;
      let client = &*context;
      let latest_block = client.info().best_hash;

      let external_key = client
        .runtime_api()
        .external_network_key(latest_block, network)
        .map_err(|_| Error::Custom("api call error".to_string()))?
        .ok_or(Error::Custom("no address for the network".to_string()))?;

      match network {
        ExternalNetworkId::Bitcoin => {
          let key = <Secp256k1 as Ciphersuite>::read_G::<&[u8]>(&mut external_key.as_slice())
            .map_err(|_| Error::Custom("invalid key stored in db".to_string()))?;

          let addr = bitcoin::Address::p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
              bitcoin::key::XOnlyPublicKey::from_slice(key.to_affine().x().as_slice()).map_err(
                |_| Error::Custom("x-coordinate for Bitcoin key was invalid".to_string()),
              )?,
            ),
            bitcoin::address::KnownHrp::Mainnet,
          );

          Ok(addr.to_string())
        }
        // We don't know the eth address before the smart contract is deployed.
        ExternalNetworkId::Ethereum => Ok(String::new()),
        ExternalNetworkId::Monero => {
          let view_private = zeroize::Zeroizing::new(
            <Ed25519 as Ciphersuite>::hash_to_F(
              b"Serai DEX Additional Key",
              &["Monero".as_bytes(), &0u64.to_le_bytes()].concat(),
            )
            .0,
          );

          let spend = <Ed25519 as Ciphersuite>::read_G::<&[u8]>(&mut external_key.as_slice())
            .map_err(|_| Error::Custom("invalid key stored in db".to_string()))?;

          let addr = monero_address::MoneroAddress::new(
            monero_address::Network::Mainnet,
            monero_address::AddressType::Featured {
              subaddress: false,
              payment_id: None,
              guaranteed: true,
            },
            *spend,
            view_private.deref() * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
          );

          Ok(addr.to_string())
        }
      }
    },
  )?;

  // add shorthand encoding rpc
  serai_json_module.register_async_method("encoded_shorthand", |params, _| async move {
    // decode using serde and encode back using scale
    let shorthand: Shorthand = params.parse()?;
    Ok(shorthand.encode())
  })?;

  // add simulating a swap path rpc
  serai_json_module.register_async_method("quote_price", |params, context| async move {
    let client = &*context;
    let latest_block = client.info().best_hash;
    let QuotePriceParams { coin1, coin2, amount, include_fee, exact_in } = params.parse()?;

    let amount = if exact_in {
      client
        .runtime_api()
        .quote_price_exact_tokens_for_tokens(latest_block, coin1, coin2, amount, include_fee)
        .map_err(|_| Error::Custom("api call error".to_string()))?
        .ok_or(Error::Custom("invalid params or empty pool".to_string()))?
    } else {
      client
        .runtime_api()
        .quote_price_tokens_for_exact_tokens(latest_block, coin1, coin2, amount, include_fee)
        .map_err(|_| Error::Custom("api call error".to_string()))?
        .ok_or(Error::Custom("invalid params or empty pool".to_string()))?
    };

    Ok(amount)
  })?;

  module.merge(serai_json_module)?;
  Ok(module)
}
