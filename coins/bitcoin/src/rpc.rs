use anyhow::Result;
use serde::de::DeserializeOwned;
use std::{fmt::Debug, str::FromStr};

use bitcoin::{
  hashes::hex::FromHex, Transaction,
};

use crate::rpc_helper::*;
use bitcoincore_rpc_json::*;

#[derive(Debug, Clone)]
pub struct Rpc {
  url: String,
}

impl Rpc {
  pub fn new(url: String) -> anyhow::Result<Rpc> {
    Ok(Rpc { url: url })
  }

  pub async fn rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: String,
    params: &[serde_json::Value],
  ) -> anyhow::Result<Response> {
    let client = reqwest::Client::new();
    let res = client
      .post(&self.url)
      .json(&RpcParams { jsonrpc: "2.0".to_string(), id: (), method, params })
      .send()
      .await?
      .text()
      .await?;
    let parsed_res: RpcResponse<Response> = serde_json::from_str(&res)
      .map_err(|_| anyhow::Error::new(RpcConnectionError::ParsingError))?;
    match parsed_res.error {
      None => Ok(parsed_res.result.unwrap()),
      Some(r) => Err(anyhow::Error::msg(r.message)), //Err(anyhow::Error::new(RpcConnectionError::ResultError(r.message))),
    }
  }

  pub async fn get_latest_block_number(&self) -> anyhow::Result<usize> {
    Ok(self.rpc_call::<usize>("getblockcount".to_string(), &[]).await?)
  }

  pub async fn get_block_number(&self, block_hash: &str) -> anyhow::Result<usize> {
    let mut ext_args = [into_json(block_hash)?];
    let defaults = [null()];
    let args = handle_defaults(&mut ext_args, &defaults);
    Ok(self.rpc_call::<GetBlockResult>("getblock".to_string(), &args).await?.height)
  }

  pub async fn get_block(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<bitcoin::Block> {
    let mut ext_args = [into_json(block_hash)?, 0.into()];
    let defaults = [null(), 0.into()];
    let args = handle_defaults(&mut ext_args, &defaults);
    let hex: String = self.rpc_call("getblock".to_string(), &args).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
    Ok(self.rpc_call::<bitcoin::BlockHash>("getbestblockhash".to_string(), &[]).await?)
  }

  pub async fn get_spendable(
    &self,
    minconf: Option<usize>,
    maxconf: Option<usize>,
    addresses: Option<Vec<&str>>,
    include_unsafe: Option<bool>,
  ) -> anyhow::Result<Vec<ListUnspentResultEntry>> {
    let mut ext_args = [
      opt_into_json(minconf)?,
      opt_into_json(maxconf)?,
      opt_into_json(addresses)?,
      opt_into_json(include_unsafe)?,
    ];
    let defaults = [into_json(1)?, into_json(9999999)?, null(), into_json(true)?];
    let args = handle_defaults(&mut ext_args, &defaults);
    Ok(self.rpc_call("listunspent".to_string(), &args).await?)
  }

  pub async fn get_o_indexes(
    &self,
    minconf: Option<usize>,
    maxconf: Option<usize>,
    addresses: Option<Vec<&str>>,
    include_unsafe: Option<bool>,
  ) -> anyhow::Result<Vec<ListUnspentResultEntry>> {
    Ok(self.get_spendable(minconf, maxconf, addresses, include_unsafe).await?)
  }

  pub async fn get_transaction(&self, tx_hash: &str) -> anyhow::Result<GetTransactionResult> {
    let mut ext_args = [into_json(tx_hash)?];
    let args = handle_defaults(&mut ext_args, &[null()]);
    Ok(self.rpc_call::<GetTransactionResult>("gettransaction".to_string(), &args).await?)
  }

  pub async fn get_transactions(
    &self,
    tx_hashes: Vec<&str>,
  ) -> anyhow::Result<Vec<GetTransactionResult>> {
    let mut transactions = Vec::<GetTransactionResult>::new();
    for one_tx in tx_hashes.iter() {
      let mut ext_args = [into_json(one_tx)?];
      let args = handle_defaults(&mut ext_args, &[null()]);
      let one_transaction = self.rpc_call::<GetTransactionResult>("gettransaction".to_string(), &args).await?;
      transactions.push(one_transaction);
    }
    Ok(transactions)
  }

  pub async fn get_block_hash(&self, height: usize) -> Result<bitcoin::BlockHash> {
    let mut ext_args = [into_json(height)?];
    let args = handle_defaults(&mut ext_args, &[null()]);
    Ok(self.rpc_call::<bitcoin::BlockHash>("getblockhash".to_string(), &args).await?)
  }

  pub async fn get_block_transactions(
    &self,
    height: usize,
  ) -> anyhow::Result<Vec<GetTransactionResult>> {
    let block_hash = self.get_block_hash(height).await.unwrap();
    let block_info = self.get_block(&block_hash).await.unwrap();
    let tx_ids: Vec<String> =
      block_info.txdata.iter().map(|one_tx| one_tx.txid().to_string()).collect();

    let tx_ids_str: Vec<&str> = tx_ids.iter().map(|s| &s[..]).collect();
    Ok(self.get_transactions(tx_ids_str).await.unwrap())
  }

  pub async fn get_raw_transaction(
    &self,
    txid: &bitcoin::Txid,
    verbose: Option<bool>,
    block_hash: Option<&bitcoin::BlockHash>,
  ) -> Result<Transaction> {
    let mut ext_args = [into_json(txid)?, opt_into_json(verbose)?, opt_into_json(block_hash)?];
    let defaults = [null(), into_json(false)?, into_json("")?];
    let args = handle_defaults(&mut ext_args, &defaults);
    let hex: String = self.rpc_call::<String>("getrawtransaction".to_string(), &args).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
    Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
  }

  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid>
  {
    let mut ext_args = [tx.raw_hex().into()];
    let args = handle_defaults(&mut ext_args, &[null()]);
    Ok(self.rpc_call::<bitcoin::Txid>("sendrawtransaction".to_string(), &args).await?)
  }

  pub async fn generate_to_address(&self, nblocks: usize, address: &str) -> Result<Vec<String>> {
    let mut ext_args = [into_json(nblocks)?, into_json(address)?, 100000000.into()];
    let defaults = [null(), null(), 100000000.into()];
    let args = handle_defaults(&mut ext_args, &defaults);
    Ok(self.rpc_call::<Vec<String>>("generatetoaddress".to_string(), &args).await.unwrap())
  }
}
