use rand_core::OsRng;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use serde_json::json;

use monero_serai::{
  Protocol, random_scalar,
  wallet::address::{Network, AddressType, AddressMeta, Address},
  rpc::{EmptyResponse, RpcError, Rpc},
};

pub async fn rpc() -> Rpc {
  let rpc = Rpc::new("http://127.0.0.1:18081".to_string());

  // Only run once
  if rpc.get_height().await.unwrap() != 1 {
    return rpc;
  }

  let addr = Address {
    meta: AddressMeta { network: Network::Mainnet, kind: AddressType::Standard },
    spend: &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
    view: &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
  }
  .to_string();

  // Mine 20 blocks to ensure decoy availability
  mine_block(&rpc, &addr).await.unwrap();
  mine_block(&rpc, &addr).await.unwrap();
  assert!(!matches!(rpc.get_protocol().await.unwrap(), Protocol::Unsupported));

  rpc
}

pub async fn mine_block(rpc: &Rpc, address: &str) -> Result<EmptyResponse, RpcError> {
  rpc
    .rpc_call(
      "json_rpc",
      Some(json!({
        "method": "generateblocks",
        "params": {
          "wallet_address": address,
          "amount_of_blocks": 10
        },
      })),
    )
    .await
}
