use anyhow::Result;
use serde::{de::DeserializeOwned};
use std::{collections::HashMap, fmt::Debug, vec::Vec, str::FromStr};

use bitcoin::{
    hashes::hex::FromHex, secp256k1::ecdsa::Signature, Address, Amount, EcdsaSighashType, OutPoint,
    PrivateKey, Transaction, BlockHash,
};

use crate::rpc_helper::{
    empty_arr, empty_obj, handle_defaults, into_json, null, opt_into_json, JsonOutPoint, RawTx,
    RpcConnectionError, RpcParams, RpcResponse, GetBlockWithDetailResult
};

use bitcoincore_rpc_json::{
    AddressType, CreateRawTransactionInput, EstimateSmartFeeResult, FundRawTransactionOptions,
    FundRawTransactionResult, GetBlockResult, GetRawTransactionResult, GetTransactionResult,
    ListUnspentResultEntry, LoadWalletResult, SignRawTransactionInput, SignRawTransactionResult,
    ListTransactionResult
};

#[derive(Debug, Clone)]
pub struct Rpc {
    url: String,
}

impl Rpc {
    pub fn new(url: String, username: String, userpass: String) -> anyhow::Result<Rpc> {
        Ok(Rpc {
            url: format!("http://{}:{}@{}", username, userpass, url),
        })
    }

    pub async fn rpc_call<Response: DeserializeOwned + Debug>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> anyhow::Result<Response> {
        let client = reqwest::Client::new();
        //println!("METHOD : ---------->");
        //dbg!(&method);
        //dbg!(&params);
        let res = client
            .post(&self.url)
            .json(&RpcParams {
                jsonrpc: "2.0",
                id: (),
                method,
                params,
            })
            .send()
            .await?
            .text()
            .await?;
        //dbg!(&res);
        let parsed_res: RpcResponse<Response> = serde_json::from_str(&res)
            .map_err(|_| anyhow::Error::new(RpcConnectionError::ParsingError))?;
        //dbg!(&parsed_res.error);
        match parsed_res.error {
            None => Ok(parsed_res.result.unwrap()),
            Some(r) => Err(anyhow::Error::msg(r.message)), //Err(anyhow::Error::new(RpcConnectionError::ResultError(r.message))),
        }
    }

    pub async fn get_height(&self) -> anyhow::Result<usize> {
        let info: usize = self.rpc_call::<usize>("getblockcount", &[]).await?;
        Ok(info)
    }

    pub async fn get_block_info(&self, block_hash: &str) -> anyhow::Result<GetBlockResult> {
        let mut ext_args = [into_json(block_hash)?];
        let defaults = [null()];
        let args = handle_defaults(&mut ext_args, &defaults);
        let info: GetBlockResult = self.rpc_call::<GetBlockResult>("getblock", &args).await?;
        Ok(info)
    }

    pub async fn get_block_index(&self, block_hash: &str) -> anyhow::Result<usize> {
        let block = self.get_block_info(block_hash).await.unwrap();
        let info = block.height;
        Ok(info)
    }

    pub async fn get_block(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<bitcoin::Block> {
        let mut ext_args = [into_json(block_hash)?, 0.into()];
        let defaults = [null(), 0.into()];
        let args = handle_defaults(&mut ext_args, &defaults);
        let hex: String = self.rpc_call("getblock", &args).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub async fn get_block_with_transactions(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<GetBlockWithDetailResult> {
        let mut ext_args = [into_json(block_hash)?, 2.into()];
        let defaults = [null(), 1.into()];
        let args = handle_defaults(&mut ext_args, &defaults);
        let info: GetBlockWithDetailResult = self.rpc_call::<GetBlockWithDetailResult>("getblock", &args).await?;
        Ok(info)
    }

    pub async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        let info = self.rpc_call::<bitcoin::BlockHash>("getbestblockhash", &[]).await?;
        Ok(info)
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
        let info = self.rpc_call("listunspent", &args).await?;
        Ok(info)
    }

    pub async fn get_o_indexes(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<Vec<&str>>,
        include_unsafe: Option<bool>,
    ) -> anyhow::Result<Vec<ListUnspentResultEntry>> {
        let info: Vec<ListUnspentResultEntry> = self
            .get_spendable(minconf, maxconf, addresses, include_unsafe)
            .await?;
        Ok(info)
    }

    pub async fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        let info: bool = self
            .rpc_call::<bool>("lockunspent", &[false.into(), outputs.into()])
            .await?;
        Ok(info)
    }

    pub async fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        let mut ext_args = [true.into(), outputs.into()];
        let args = handle_defaults(&mut ext_args, &[true.into(), empty_arr()]);
        let info: bool = self.rpc_call::<bool>("lockunspent", &args).await?;
        Ok(info)
    }

    pub async fn get_fee_per_byte(&self, conf_target: Option<usize>) -> anyhow::Result<u64> {
        let mut ext_args = [opt_into_json(conf_target)?];
        let defaults = [into_json(100)?];
        let args = handle_defaults(&mut ext_args, &defaults);
        let fee: EstimateSmartFeeResult = self
            .rpc_call::<EstimateSmartFeeResult>("estimatesmartfee", &args)
            .await?;
        Ok(fee.fee_rate.unwrap().to_sat())
    }

    pub async fn get_transaction(&self, tx_hash: &str) -> anyhow::Result<GetTransactionResult> {
        let mut ext_args = [into_json(tx_hash)?];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let tx = self
            .rpc_call::<GetTransactionResult>("gettransaction", &args)
            .await?;
        Ok(tx)
    }

    pub async fn get_transactions(
        &self,
        tx_hashes: Vec<&str>,
    ) -> anyhow::Result<Vec<GetTransactionResult>> {
        let mut transactions = Vec::<GetTransactionResult>::new();
        for one_tx in tx_hashes.iter() {
            let mut ext_args = [into_json(one_tx)?];
            let args = handle_defaults(&mut ext_args, &[null()]);
            let one_transaction = self
                .rpc_call::<GetTransactionResult>("gettransaction", &args)
                .await?;
            transactions.push(one_transaction);
        }
        Ok(transactions)
    }
    

    pub async fn get_raw_transactions(
        &self,
        tx_hashes: Vec<&str>,
        block_hash : Option<&BlockHash>,
    ) -> anyhow::Result<Vec<Transaction>> {
        let mut transactions = Vec::<Transaction>::new();
        for one_tx in tx_hashes.iter() {
            let one_transaction = self.get_raw_transaction(&bitcoin::Txid::from_str(one_tx).unwrap(), None, block_hash).await.unwrap();
            transactions.push(one_transaction);
        }
        Ok(transactions)
    }

    pub async fn is_confirmed(&self, tx_hash: &str) -> anyhow::Result<bool> {
        let tx_block_number = self.get_transaction_block_number(&tx_hash).await?;
        Ok((self.get_height().await?.saturating_sub(tx_block_number) + 1) >= 10)
    }

    pub async fn get_transaction_block_number(&self, tx_hash: &str) -> anyhow::Result<usize> {
        let mut ext_args = [into_json(tx_hash)?];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let tx = self
            .rpc_call::<GetTransactionResult>("gettransaction", &args)
            .await?;
        Ok(tx.info.blockheight.unwrap() as usize)
    }

    pub async fn get_block_hash(&self, height: usize) -> Result<bitcoin::BlockHash> {
        let mut ext_args = [into_json(height)?];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let info: bitcoin::BlockHash = self
            .rpc_call::<bitcoin::BlockHash>("getblockhash", &args)
            .await?;
        Ok(info)
    }

    pub async fn get_block_transactions(
        &self,
        height: usize,
    ) -> anyhow::Result<Vec<GetTransactionResult>> {
        let block_hash = self.get_block_hash(height).await.unwrap();
        let block_info = self.get_block(&block_hash).await.unwrap();
        let tx_ids: Vec<String> = block_info.txdata.iter().map(|one_tx| one_tx.txid().to_string()).collect();
        
        let tx_ids_str: Vec<&str> = tx_ids.iter().map(|s| &s[..]).collect();
        let transactions = self.get_transactions(tx_ids_str).await.unwrap();
        Ok(transactions)
    }

    pub async fn get_block_raw_transactions(
        &self,
        height: usize,
    ) -> anyhow::Result<Vec<Transaction>> {
        let block_hash = self.get_block_hash(height).await.unwrap();
        let block_info = self.get_block(&block_hash).await.unwrap();
        let tx_ids: Vec<String> = block_info.txdata.iter().map(|one_tx| one_tx.txid().to_string()).collect();
        
        let tx_ids_str: Vec<&str> = tx_ids.iter().map(|s| &s[..]).collect();
        let transactions = self.get_raw_transactions(tx_ids_str, Some(&block_hash)).await.unwrap();
        Ok(transactions)
    }

    pub async fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        verbose: Option<bool>,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        let mut ext_args = [
            into_json(txid)?,
            opt_into_json(verbose)?,
            opt_into_json(block_hash)?,
        ];
        let defaults = [null(), into_json(false)?, into_json("")?];
        let args = handle_defaults(&mut ext_args, &defaults);
        let hex: String = self.rpc_call::<String>("getrawtransaction", &args).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub async fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        let mut ext_args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        let args = handle_defaults(&mut ext_args, &[null()]);
        self.rpc_call::<String>("getrawtransaction", &args).await
    }

    pub async fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<GetRawTransactionResult> {
        let mut ext_args = [
            into_json(txid)?,
            into_json(true)?,
            opt_into_json(block_hash)?,
        ];
        let args = handle_defaults(&mut ext_args, &[null()]);
        self.rpc_call::<GetRawTransactionResult>("getrawtransaction", &args)
            .await
    }

    pub async fn create_raw_transaction_hex(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outs.iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_btc()))),
        );
        let mut ext_args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults = [null(), null(), into_json(0)?, into_json(false)?];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<String>("createrawtransaction", &args).await
    }

    pub async fn create_raw_transaction(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        let hex: String = self
            .create_raw_transaction_hex(utxos, outs, locktime, replaceable)
            .await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub async fn fund_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        options: Option<&FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<FundRawTransactionResult>
    where
        R: Sync + Send,
    {
        let mut ext_args = [
            tx.raw_hex().into(),
            opt_into_json(options)?,
            opt_into_json(is_witness)?,
        ];
        let defaults = [empty_obj(), null()];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call("fundrawtransaction", &args).await
    }

    #[deprecated]
    pub async fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[SignRawTransactionInput]>,
        private_keys: Option<&[PrivateKey]>,
        sighash_type: Option<EcdsaSighashType>,
    ) -> Result<SignRawTransactionResult>
    where
        R: Sync + Send,
    {
        let mut ext_args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [null(), empty_arr(), empty_arr(), into_json("ALL")?];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<SignRawTransactionResult>("signrawtransaction", &args)
            .await
    }

    pub async fn sign_raw_transaction_with_wallet<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[SignRawTransactionInput]>,
        sighash_type: Option<EcdsaSighashType>,
    ) -> Result<SignRawTransactionResult>
    where
        R: Sync + Send,
    {
        let mut ext_args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [null(), empty_arr(), into_json("ALL")?];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<SignRawTransactionResult>("signrawtransactionwithwallet", &args)
            .await
    }

    pub async fn sign_raw_transaction_with_key<R: RawTx>(
        &self,
        tx: R,
        privkeys: &[PrivateKey],
        prevtxs: Option<&[SignRawTransactionInput]>,
        sighash_type: Option<EcdsaSighashType>,
    ) -> Result<SignRawTransactionResult>
    where
        R: Sync + Send,
    {
        let mut ext_args = [
            tx.raw_hex().into(),
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null(), empty_arr(), into_json("ALL")?];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<SignRawTransactionResult>("signrawtransactionwithkey", &args)
            .await
    }

    pub async fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<bitcoin::Txid>
    where
        R: Sync + Send,
    {
        let mut ext_args = [tx.raw_hex().into()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let info: bitcoin::Txid = self
            .rpc_call::<bitcoin::Txid>("sendrawtransaction", &args)
            .await?;
        Ok(info)
    }

    pub async fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let mut ext_args = [
            address.to_string().into(),
            signature.to_string().into(),
            into_json(message)?,
        ];
        let defaults = [null(), null(), null()];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<bool>("verifymessage", &args).await
    }

    pub async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<AddressType>,
    ) -> Result<Address> {
        let mut ext_args = [opt_into_json(label)?, opt_into_json(address_type)?];
        let defaults = [into_json("")?, into_json(AddressType::Legacy)?];
        let args = handle_defaults(&mut ext_args, &defaults);
        self.rpc_call::<Address>("getnewaddress", &args).await
    }

    pub async fn generate_to_address(&self, nblocks: usize, address: &str) -> Result<Vec<String>> {
        let mut ext_args = [into_json(nblocks)?, into_json(address)?];
        let defaults = [null(), null()];
        let args = handle_defaults(&mut ext_args, &defaults);
        let info = self
            .rpc_call::<Vec<String>>("generatetoaddress", &args)
            .await
            .unwrap();
        Ok(info)
    }

    pub async fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let mut ext_args = [
            "*".into(),
            opt_into_json(minconf)?,
            opt_into_json(include_watchonly)?,
        ];
        let defaults = [0.into(), null()];
        let args = handle_defaults(&mut ext_args, &defaults);
        Ok(Amount::from_btc(self.rpc_call("getbalance", &args).await?)?)
    }

    pub async fn decode_raw_transaction<R: RawTx>(&self, tx: R) -> Result<GetBlockResult>
    where
        R: Sync + Send,
    {
        let mut ext_args = [tx.raw_hex().into()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        self.rpc_call::<GetBlockResult>("decoderawtransaction", &args)
            .await
    }

    pub async fn create_wallet(
        &self,
        wallet_name: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
        descriptors: Option<bool>,
        load_on_startup: Option<bool>,
    ) -> Result<LoadWalletResult> {
        let mut ext_args = [
            into_json(wallet_name)?,
            opt_into_json(disable_private_keys)?,
            opt_into_json(blank)?,
            opt_into_json(passphrase)?,
            opt_into_json(avoid_reuse)?,
            opt_into_json(descriptors)?,
            opt_into_json(load_on_startup)?,
        ];
        let defaults = [
            null(),
            into_json(false)?,
            into_json(false)?,
            into_json("")?,
            into_json(false)?,
            into_json(false)?,
            null(),
        ];
        let args = handle_defaults(&mut ext_args, &defaults);
        let info = self
            .rpc_call::<LoadWalletResult>("createwallet", &args)
            .await?;
        Ok(info)
    }

    pub async fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<ListTransactionResult>> {
        let mut ext_args = [
            label.unwrap_or("*").into(),
            opt_into_json(count)?,
            opt_into_json(skip)?,
            opt_into_json(include_watchonly)?,
        ];
        let defaults = [10.into(), 0.into(), null()];
        let args = handle_defaults(&mut ext_args, &defaults);

        let info = self.rpc_call::<Vec<ListTransactionResult>>("listtransactions", &args).await?;
        Ok(info)
    }
}
