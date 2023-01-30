use core::fmt::Debug;

use serde::de::DeserializeOwned;
use serde_json::Value::Null;

use bitcoin::{
  hashes::hex::{FromHex, ToHex},
  Transaction,
};
use bitcoincore_rpc_json::*;
use crate::rpc_helper::*;
use crate::json_helper::*;

#[derive(Debug, Clone)]
pub struct Rpc {
  url: String,
}

impl Rpc {
  pub fn new(url: String) -> Result<Rpc, RpcError> {
    Ok(Rpc { url })
  }

  pub async fn rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: &[serde_json::Value],
  ) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let res = client
      .post(&self.url)
      .json(&RpcParams { jsonrpc: "2.0".into(), id: (), method: method.into(), params })
      .send()
      .await?
      .text()
      .await?;

    let parsed_res: RpcResponse<Response> =
      serde_json::from_str(&res).map_err(|_| RpcError::ParsingError)?;

    match parsed_res {
      RpcResponse::Err { error } => Err(RpcError::CustomError(error)),
      RpcResponse::Ok { result } => Ok(result),
    }
  }

  pub async fn get_latest_block_number(&self) -> Result<usize, RpcError> {
    self.rpc_call::<usize>("getblockcount", &[]).await
  }

  pub async fn get_block_number(&self, block_hash: &str) -> Result<usize, RpcError> {
    Ok(self.rpc_call::<GetBlockResult>("getblock", &[into_json(block_hash)?]).await?.height)
  }

  pub async fn get_block(
    &self,
    block_hash: &bitcoin::BlockHash,
  ) -> Result<bitcoin::Block, RpcError> {
    let hex: String = self.rpc_call("getblock", &[into_json(block_hash)?, 0.into()]).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, RpcError> {
    self.rpc_call::<bitcoin::BlockHash>("getbestblockhash", &[]).await
  }

  pub async fn get_block_hash(&self, height: usize) -> Result<bitcoin::BlockHash, RpcError> {
    self.rpc_call::<bitcoin::BlockHash>("getblockhash", &[into_json(height)?]).await
  }

  pub async fn get_transaction(
    &self,
    txid: &bitcoin::Txid,
    verbose: Option<bool>,
    block_hash: Option<&bitcoin::BlockHash>,
  ) -> Result<Transaction, RpcError> {
    let mut ext_args = [into_json(txid)?, opt_into_json(verbose)?, opt_into_json(block_hash)?];
    let defaults = [Null, into_json(false)?, into_json("")?];
    let args = handle_defaults(&mut ext_args, &defaults);
    let hex: String = self.rpc_call::<String>("getrawtransaction", args).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, RpcError> {
    self
      .rpc_call::<bitcoin::Txid>(
        "sendrawtransaction",
        &[bitcoin::consensus::encode::serialize(tx).to_vec().to_hex().into()],
      )
      .await
  }
}
