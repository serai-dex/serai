use serde_json::json;

use monero_serai::rpc::{EmptyResponse, RpcError, Rpc};

pub async fn mine_block(rpc: &Rpc, address: String) -> Result<EmptyResponse, RpcError> {
  rpc.rpc_call("json_rpc", Some(json!({
    "method": "generateblocks",
    "params": {
      "wallet_address": address,
      "amount_of_blocks": 10
    },
  }))).await
}
