use std::{sync::Arc, ops::Deref, collections::HashSet};

use rand_core::{RngCore, OsRng};

use sp_core::Encode;
use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_abi::{primitives::prelude::*, SubstrateBlock as Block};

use tokio::sync::RwLock;

use jsonrpsee::RpcModule;

use sc_client_api::BlockBackend;
use sc_transaction_pool_api::TransactionPool;

mod blockchain;
mod p2p_validators;

pub struct FullDeps<C, P> {
  pub id: String,
  pub client: Arc<C>,
  pub pool: Arc<P>,
  pub authority_discovery: Option<sc_authority_discovery::Service>,
}

pub fn create_full<
  C: 'static
    + Send
    + Sync
    + ProvideRuntimeApi<Block, Api: BlockBuilder<Block> + serai_runtime::SeraiApi<Block>>
    + HeaderBackend<Block>
    + HeaderMetadata<Block, Error = BlockchainError>
    + BlockBackend<Block>,
  P: 'static + TransactionPool,
>(
  deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>> {
  let FullDeps { id, client, pool, authority_discovery } = deps;

  let mut root = RpcModule::new(());
  root.merge(blockchain::module(client.clone())?)?;
  if let Some(authority_discovery) = authority_discovery {
    root.merge(p2p_validators::module(id, client, authority_discovery)?)?;
  }
  Ok(root)

  /* TODO
  use ciphersuite::{GroupIo, WithPreferredHash};
  use ciphersuite_kp256::{k256::elliptic_curve::point::AffineCoordinates, Secp256k1};
  use dalek_ff_group::Ed25519;
  use bitcoin_serai::bitcoin;

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
}
