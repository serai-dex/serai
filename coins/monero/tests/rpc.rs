use rand::rngs::OsRng;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use serde_json::json;

use monero::{
  network::Network,
  util::{key::PublicKey, address::Address}
};

use monero_serai::{random_scalar, rpc::{EmptyResponse, RpcError, Rpc}};

pub async fn rpc() -> Rpc {
  let rpc = Rpc::new("http://127.0.0.1:18081".to_string());

  // Only run once
  if rpc.get_height().await.unwrap() != 1 {
    return rpc;
  }

  let addr = Address::standard(
    Network::Mainnet,
    PublicKey { point: (&random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE).compress() },
    PublicKey { point: (&random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE).compress() }
  ).to_string();

  // Mine 10 blocks so we have 10 decoys so decoy selection doesn't fail
  mine_block(&rpc, &addr).await.unwrap();

  rpc
}

pub async fn mine_block(rpc: &Rpc, address: &str) -> Result<EmptyResponse, RpcError> {
  rpc.rpc_call("json_rpc", Some(json!({
    "method": "generateblocks",
    "params": {
      "wallet_address": address,
      "amount_of_blocks": 10
    },
  }))).await
}
