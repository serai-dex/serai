#![expect(unused_imports)]

use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_runtime::{
  in_instructions::primitives::Shorthand,
  primitives::{ExternalNetworkId, NetworkId, PublicKey, SubstrateAmount, QuotePriceParams},
  // validator_sets::ValidatorSetsApi,
  dex::DexApi,
  Block,
  Nonce,
  SeraiRuntimeApi,
};

use tokio::sync::RwLock;

use jsonrpsee::RpcModule;
// use scale::Encode;

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
    + DexApi<Block>
    + BlockBuilder<Block>,
{
  use substrate_frame_rpc_system::{System, SystemApiServer};
  use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
  use ciphersuite::{GroupIo, WithPreferredHash};
  use ciphersuite_kp256::{k256::elliptic_curve::point::AffineCoordinates, Secp256k1};
  use dalek_ff_group::Ed25519;
  use bitcoin_serai::bitcoin;

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

  /* TODO
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
          let key = <Secp256k1 as GroupIo>::read_G::<&[u8]>(&mut external_key.as_slice())
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
          // TODO: Serai view-key crate
          let view_private = zeroize::Zeroizing::new(<Ed25519 as WithPreferredHash>::hash_to_F(
            &["Monero".as_bytes(), &0u64.to_le_bytes()].concat(),
          ));

          let spend = <Ed25519 as GroupIo>::read_G::<&[u8]>(&mut external_key.as_slice())
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
  */

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
