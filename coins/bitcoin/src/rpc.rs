use anyhow::Result;
use serde::de::DeserializeOwned;
use std::{collections::HashMap, fmt::Debug, vec::Vec};

use bitcoin::{
    hashes::hex::FromHex, secp256k1::ecdsa::Signature, Address, Amount, OutPoint, PrivateKey,
    Transaction,
};

use crate::json_rpc::{
    empty_arr, empty_obj, handle_defaults, into_json, null, opt_into_json,
    CreateRawTransactionInput, EcdsaSighashType, EstimateSmartFeeResult, FullParams,
    FundRawTransactionOptions, FundRawTransactionResult, GetBlockResult, GetRawTransactionResult,
    GetTransactionResult, JsonOutPoint, ListUnspentResultEntry, NewResponse, RawTx, RpcError,
    SignRawTransactionInput, SignRawTransactionResult, UnspentInputResponse,
};

#[derive(Debug, Clone)]
pub struct Rpc {
    url: String,
}

impl Rpc {
    pub fn new(url: String, username: String, userpass: String) -> anyhow::Result<Rpc> {
        let full_url = format!("http://{}:{}@{}", username, userpass, url);
        Ok(Rpc {
            url: full_url.clone(),
        })
    }

    pub async fn rpc_call<Response: DeserializeOwned + Debug>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> anyhow::Result<Response> {
        let client = reqwest::Client::new();
        let res = client
            .post(&self.url)
            .json(&FullParams {
                jsonrpc: "2.0",
                id: (),
                method,
                params,
            })
            .send()
            .await?
            .text()
            .await?;

        let parsed_res: NewResponse<Response> = serde_json::from_str(&res)
            .map_err(|_| anyhow::Error::new(RpcError::ParsingError))?;
        match parsed_res.error {
            None => Ok(parsed_res.result.unwrap()),
            Some(..) => Err(anyhow::Error::new(RpcError::ResultError)),
        }
    }

    pub async fn get_height(&self) -> anyhow::Result<usize> {
        let info: usize = self.rpc_call::<usize>("getblockcount", &[]).await?;
        Ok(info)
    }

    pub async fn get_block(&self, block_hash: &str) -> anyhow::Result<GetBlockResult> {
        let mut ext_args = [into_json(block_hash)?];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let info: GetBlockResult = self.rpc_call::<GetBlockResult>("getblock", &args).await?;
        Ok(info)
    }

    pub async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        let info : bitcoin::BlockHash = self.rpc_call::<bitcoin::BlockHash>("getbestblockhash", &[]).await?;
        Ok(info)
    }

    pub async fn get_spendable(&self, address: &str) -> anyhow::Result<Vec<UnspentInputResponse>> {
        let mut ext_args = [into_json(address)?];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let info = self.rpc_call("listunspent", &args).await?;
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
        let info: bool = self
            .rpc_call::<bool>("lockunspent", &[true.into(), outputs.into()])
            .await?;
        Ok(info)
    }

    pub async fn get_o_indexes(
        &self,
        addresses: Vec<&str>,
    ) -> anyhow::Result<Vec<ListUnspentResultEntry>> {
        let mut ext_args = [into_json(6)?, into_json(99999999)?, into_json(addresses)?];

        let args = handle_defaults(
            &mut ext_args,
            &[into_json(6)?, into_json(99999999)?, empty_arr()],
        );
        let info: Vec<ListUnspentResultEntry> = self
            .rpc_call::<Vec<ListUnspentResultEntry>>("listunspent", &args)
            .await?;
        Ok(info)
    }

    pub async fn get_fee_per_byte(&self) -> anyhow::Result<u64> {
        let mut ext_args = [into_json(100).unwrap()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let fee: EstimateSmartFeeResult = self
            .rpc_call::<EstimateSmartFeeResult>("estimatesmartfee", &args)
            .await?;
        Ok(fee.fee_rate.unwrap().to_sat())
    }

    pub async fn get_transaction(&self, tx_hash: &str) -> anyhow::Result<GetTransactionResult> {
        let mut ext_args = [into_json(tx_hash).unwrap()];
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
            let mut ext_args = [into_json(one_tx).unwrap()];

            let args = handle_defaults(&mut ext_args, &[null()]);
            let one_transaction = self
                .rpc_call::<GetTransactionResult>("gettransaction", &args)
                .await?;
            transactions.push(one_transaction);
        }
        Ok(transactions)
    }

    pub async fn is_confirmed(&self, tx_hash: &str) -> anyhow::Result<bool> {
        let tx_block_number = self.get_transaction_block_number(&tx_hash).await?;
        Ok((self.get_height().await?.saturating_sub(tx_block_number) + 1) >= 10)
    }

    pub async fn get_transaction_block_number(&self, tx_hash: &str) -> anyhow::Result<usize> {
        let mut ext_args = [into_json(tx_hash).unwrap()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let tx = self
            .rpc_call::<GetTransactionResult>("gettransaction", &args)
            .await?;
        Ok(tx.info.blockheight.unwrap() as usize)
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        let info : bitcoin::BlockHash = self.rpc_call::<bitcoin::BlockHash>("getblockhash", &[height.into()]).await?;
        Ok(info)
    }

    pub async fn get_block_transactions(
        &self,
        height: usize,
    ) -> anyhow::Result<Vec<GetTransactionResult>> {
        //-> anyhow::Result<GetBlockResult> {
        let mut ext_args = [into_json(height).unwrap()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let tx_hash = self.rpc_call::<String>("getblockhash", &args).await?;

        let mut ext_args = [into_json(tx_hash).unwrap()];
        let args = handle_defaults(&mut ext_args, &[null()]);
        let block_info: GetBlockResult = self.rpc_call::<GetBlockResult>("getblock", &args).await?;
        let tx_ids: Vec<String> = block_info
            .tx
            .iter()
            .map(|one_tx| one_tx.to_string())
            .collect();
        let tx_ids_str: Vec<&str> = tx_ids.iter().map(|s| &s[..]).collect();
        let transactions = self.get_transactions(tx_ids_str).await.unwrap();
        Ok(transactions)
    }

    pub async fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        let mut args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        let args = handle_defaults(&mut args, &[null()]);
        let hex: String = self.rpc_call::<String>("getrawtransaction", &args).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    pub async fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        let mut args = [
            into_json(txid)?,
            into_json(false)?,
            opt_into_json(block_hash)?,
        ];
        let args = handle_defaults(&mut args, &[null()]);
        self.rpc_call::<String>("getrawtransaction", &args).await
    }

    pub async fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<GetRawTransactionResult> {
        let mut args = [
            into_json(txid)?,
            into_json(true)?,
            opt_into_json(block_hash)?,
        ];
        self.rpc_call::<GetRawTransactionResult>(
            "getrawtransaction",
            handle_defaults(&mut args, &[null()]),
        )
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
                .map(|(k, v)| (k.clone(), serde_json::Value::from(v.as_btc()))),
        );
        let mut args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults = [into_json(0i64)?, null()];
        self.rpc_call::<String>(
            "createrawtransaction",
            handle_defaults(&mut args, &defaults),
        )
        .await
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
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(options)?,
            opt_into_json(is_witness)?,
        ];
        let defaults = [empty_obj(), null()];
        self.rpc_call("fundrawtransaction", handle_defaults(&mut args, &defaults))
            .await
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
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), empty_arr(), null()];
        self.rpc_call::<SignRawTransactionResult>(
            "signrawtransaction",
            handle_defaults(&mut args, &defaults),
        )
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
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null()];
        self.rpc_call::<SignRawTransactionResult>(
            "signrawtransactionwithwallet",
            handle_defaults(&mut args, &defaults),
        )
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
        let mut args = [
            tx.raw_hex().into(),
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null()];
        self.rpc_call::<SignRawTransactionResult>(
            "signrawtransactionwithkey",
            handle_defaults(&mut args, &defaults),
        )
        .await
    }

    pub async fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<bitcoin::Txid>
    where
        R: Sync + Send,
    {
        //let test = &tx.raw_hex();
        //dbg!(&test);
        let info : bitcoin::Txid = self.rpc_call::<bitcoin::Txid>("sendrawtransaction", &[tx.raw_hex().into()]).await?;
        Ok(info)
    }

    pub async fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [
            address.to_string().into(),
            signature.to_string().into(),
            into_json(message)?,
        ];
        self.rpc_call::<bool>("verifymessage", &args).await
    }
}
