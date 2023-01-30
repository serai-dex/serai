use serde::de::DeserializeOwned;
use std::{fmt::Debug, str::FromStr, result::Result};
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
    Ok(Rpc { url: url })
  }

  pub async fn rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: String,
    params: &[serde_json::Value],
  ) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let res = client
      .post(&self.url)
      .json(&RpcParams { jsonrpc: "2.0".to_string(), id: (), method, params })
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
    Ok(self.rpc_call::<usize>("getblockcount".to_string(), &[]).await?)
  }

  pub async fn get_block_number(&self, block_hash: &str) -> Result<usize, RpcError> {
    let mut ext_args = [into_json(block_hash)?];
    let defaults = [Null];
    let args = handle_defaults(&mut ext_args, &defaults);
    Ok(self.rpc_call::<GetBlockResult>("getblock".to_string(), &args).await?.height)
  }

  pub async fn get_block(
    &self,
    block_hash: &bitcoin::BlockHash,
  ) -> Result<bitcoin::Block, RpcError> {
    let mut ext_args = [into_json(block_hash)?, 0.into()];
    let defaults = [Null, 0.into()];
    let args = handle_defaults(&mut ext_args, &defaults);
    let hex: String = self.rpc_call("getblock".to_string(), &args).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, RpcError> {
    Ok(self.rpc_call::<bitcoin::BlockHash>("getbestblockhash".to_string(), &[]).await?)
  }

  pub async fn get_spendable(
    &self,
    minconf: Option<usize>,
    maxconf: Option<usize>,
    addresses: Option<Vec<&str>>,
    include_unsafe: Option<bool>,
  ) -> Result<Vec<ListUnspentResultEntry>, RpcError> {
    let mut ext_args = [
      opt_into_json(minconf)?,
      opt_into_json(maxconf)?,
      opt_into_json(addresses)?,
      opt_into_json(include_unsafe)?,
    ];
    let defaults = [into_json(1)?, into_json(9999999)?, Null, into_json(true)?];
    let args = handle_defaults(&mut ext_args, &defaults);
    Ok(self.rpc_call("listunspent".to_string(), &args).await?)
  }

  pub async fn get_o_indexes(
    &self,
    minconf: Option<usize>,
    maxconf: Option<usize>,
    addresses: Option<Vec<&str>>,
    include_unsafe: Option<bool>,
  ) -> Result<Vec<ListUnspentResultEntry>, RpcError> {
    Ok(self.get_spendable(minconf, maxconf, addresses, include_unsafe).await?)
  }

  pub async fn get_block_hash(&self, height: usize) -> Result<bitcoin::BlockHash, RpcError> {
    let mut ext_args = [into_json(height)?];
    let args = handle_defaults(&mut ext_args, &[Null]);
    Ok(self.rpc_call::<bitcoin::BlockHash>("getblockhash".to_string(), &args).await?)
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
    let hex: String = self.rpc_call::<String>("getrawtransaction".to_string(), &args).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, RpcError> {
    let mut ext_args = [bitcoin::consensus::encode::serialize(tx).to_vec().to_hex().into()];
    let args = handle_defaults(&mut ext_args, &[Null]);
    Ok(self.rpc_call::<bitcoin::Txid>("sendrawtransaction".to_string(), &args).await?)
  }
}
