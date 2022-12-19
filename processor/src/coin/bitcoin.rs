use std::{str::FromStr, io::Read, fs::read_to_string,collections::HashMap};

use async_trait::async_trait;

use rand_core::le::read_u32_into;
use transcript::RecommendedTranscript;
use frost::{ curve::{Secp256k1, Ciphersuite}, ThresholdKeys };

use serde::Deserialize;

use bitcoin_hashes::hex::FromHex;

use bitcoin::{util::address::Address, Txid, schnorr::{TweakedPublicKey,SchnorrSig}, XOnlyPublicKey, psbt::PartiallySignedTransaction, hashes::sha256d::Hash};
use bitcoin_serai::{rpc::Rpc,rpc_helper::RawTx, crypto::{make_even, taproot_sighash}, wallet::SpendableOutput};
use bitcoincore_rpc_json::{AddressType, ListUnspentResultEntry};

use k256::{ProjectivePoint, elliptic_curve::{sec1::{ToEncodedPoint,Tag}}, Scalar};
use crate::{
  coin::{CoinError, Output as OutputTrait, Coin},
};

//Todo: Delete it later
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64,
  pub mask: u64,
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    ((((self.per_weight * u64::try_from(weight).unwrap()) - 1) / self.mask) + 1) * self.mask
  }
}

#[derive(Clone, Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Rpc,
}

impl Bitcoin {
  pub async fn new(url: String, username:Option<String>, userpass:Option<String>) -> Bitcoin {
    Bitcoin {
      rpc: Rpc::new(url, username.unwrap(), userpass.unwrap()).unwrap(),
    }
  }
}

//TODO: Implement proper Structs
//use zeroize::{Zeroize, ZeroizeOnDrop};
//use bitcoin_serai::rpc_helper::RpcError;
use monero_serai::{transaction::Transaction,wallet::{TransactionMachine}};


#[derive(Clone, Debug)]
pub struct Output(SpendableOutput);
impl From<SpendableOutput> for Output {
  fn from(output: SpendableOutput) -> Output {
    Output(output)
  }
}
impl OutputTrait for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While the Monero library offers a variant which allows senders to ensure their TXs have unique
  // output keys, Serai can still be targeted using the classic burning bug
  type Id = [u8; 36];

  fn id(&self) -> Self::Id {
    let serialized_data = self.0.serialize();
    let ret : [u8; 36] = serialized_data[0..36].try_into().unwrap();
    ret
  }

  fn amount(&self) -> u64 {
    self.0.amount
  }

  fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    SpendableOutput::deserialize(reader).map(Output)
  }
}

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction =  Transaction;//bitcoin::Transaction;
  type Block = bitcoin::Block;

  type Output = Output;
  type SignableTransaction = PartiallySignedTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 10;

  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: ProjectivePoint) -> Self::Address {
    assert!(key.to_encoded_point(true).tag() == Tag::CompressedOddY, "YKey is odd");
    //let pubkey = bitcoin::util::key::PublicKey::from_slice(key.to_encoded_point(true).as_bytes()).unwrap();
    let xonly_pubkey = XOnlyPublicKey::from_slice(&key.to_encoded_point(true).x().to_owned().unwrap()).unwrap();
    let tweaked_pubkey = bitcoin::schnorr::TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    
    Address::p2tr_tweaked(tweaked_pubkey, bitcoin::network::constants::Network::Regtest)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // - defines height as chain length, so subtract 1 for block number
    let block_result = self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError);
    let block_number = match block_result {
      Ok(val) => Ok(val as usize),
      Err(_) => return Err(CoinError::ConnectionError),
    };

    return block_number;
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let block_hash = self.rpc.get_block_hash(number - 1).await.unwrap();
    let info = self.rpc.get_block(&block_hash).await.unwrap();
    Ok(info)
  }

  async fn is_confirmed(&self, tx: &[u8]) -> Result<bool, CoinError> {
    let txid_str = String::from_utf8(tx.to_vec()).unwrap();
    let tx_block_number = self.rpc.get_transaction_block_number(&txid_str.to_string()).await.unwrap();
    Ok((self.get_latest_block_number().await.unwrap().saturating_sub(tx_block_number) + 1) >= 10)
  }

  //TODO: 
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: ProjectivePoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let main_addr = self.address(key);
    //dbg!(&main_addr);
    let block_details = self.rpc.get_block_with_transactions(&block.block_hash()).await.unwrap();
    //dbg!(&main_addr.script_pubkey());
    let mut outputs = Vec::new();
    for one_transaction in block_details.tx {
      for output_tx in one_transaction.vout {
        dbg!(&output_tx.script_pub_key);
        //if output_tx.script_pub_key.script().unwrap().cmp(&main_addr.script_pubkey()).is_eq() {
          println!("It is spendable");
          outputs.push(Output(SpendableOutput{
            txid:one_transaction.txid,
            vout:output_tx.n,
            amount:output_tx.value.to_sat()
          }));
        //}
      }
    }
    dbg!(&outputs);
    return Ok(outputs);
    //return Err(CoinError::ConnectionError);
  }

  //TODO: Add sending logic
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Secp256k1>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut inputs: Vec<Output>,
    payments: &[(Address, u64)],
    fee: Fee,
  ) -> Result<Self::SignableTransaction, CoinError> {
    let spend = keys.group_key();
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add sending logic
  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError> {
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add publishing logic
  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    return Err(CoinError::ConnectionError);
    //self.rpc.publish_transaction(tx).await.map_err(|_| CoinError::ConnectionError)?;

    //Ok((tx.hash().to_vec(), tx.prefix.outputs.iter().map(|output| output.key.to_bytes()).collect()))
  }
  
  async fn tweak_keys(keys : &mut HashMap<u16, ThresholdKeys<Self::Curve>>) -> &mut HashMap<u16, ThresholdKeys<Self::Curve>> {
    for (_, one_key) in keys.iter_mut() {
      let (_, offset) = make_even(one_key.group_key());
      *one_key = one_key.offset(Scalar::from(offset));
    }
    keys
  }

  #[cfg(test)] //42 satoshi / byte
  async fn get_fee(&self) -> Self::Fee {
    Self::Fee { per_weight: 42, mask: 66 }
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    let new_addr = self.rpc.get_new_address(None, Some(AddressType::Bech32)).await.unwrap();
    self.rpc.generate_to_address(1, new_addr.to_string().as_str()).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    dbg!(&address);
    let from_addr = &address;
    let mut utxos = self.rpc.get_spendable(None, None, Some(vec![from_addr.to_string().as_str()]), None).await.unwrap();
    //dbg!(&utxos);
    let mut txin_list_complete = Vec::new();
    
    let fee_amount_sat = bitcoin::Amount::from_sat(100000);
    let send_amount_sat = bitcoin::Amount::from_sat(15341521000);
    let total_amount_sat = fee_amount_sat.checked_add(send_amount_sat).unwrap();

    let mut sum_sat = bitcoin::Amount::from_sat(0);
    let mut diff_sat = bitcoin::Amount::from_sat(9999999999999);
    let mut temp_diff_sat = bitcoin::Amount::from_sat(0);
    let mut utxo_id = 0;
    let mut changed_amount_sat = bitcoin::Amount::from_sat(0);

    let it = utxos.iter();
    for (i, one_utx) in it.enumerate() {
        if one_utx.amount.checked_sub(total_amount_sat).is_some() {
            temp_diff_sat = one_utx.amount.checked_sub(total_amount_sat).unwrap();
            if temp_diff_sat < diff_sat {
                diff_sat = temp_diff_sat;
                utxo_id = i + 1;

                changed_amount_sat = temp_diff_sat;
            } 
        }
        
        sum_sat = sum_sat.checked_add(one_utx.amount).unwrap();
    }

    if total_amount_sat > sum_sat {
        panic!("No way to reach that much of bitcoin to send !");
    }

    if utxo_id == 0 {
        println!("No utxo found - Total : {}",sum_sat.to_sat());
        utxos.sort_by(|k1:&ListUnspentResultEntry, k2:&ListUnspentResultEntry| {
            k2.amount.cmp(&k1.amount)
        });
        sum_sat = bitcoin::Amount::from_sat(0);
        let it = utxos.iter();
        for (i, one_utx) in it.enumerate() {
            sum_sat = sum_sat.checked_add(one_utx.amount).unwrap();
            txin_list_complete.push(&utxos[i]);
            if sum_sat > total_amount_sat {
                changed_amount_sat = sum_sat.checked_sub(total_amount_sat).unwrap();
                break;
            }
        }
        println!(
            "Sum : {}  Target: {}   Change: {}",
            sum_sat.to_sat(),
            total_amount_sat.to_sat(),
            changed_amount_sat.to_sat()
        );
    }
    else {
        txin_list_complete.push(&utxos[utxo_id-1]);
    }

    println!(
      "Total Amount: {} Diff sat: {}  -  Diff Btc: {}, Best ID : {} Change:{}",
      total_amount_sat.to_btc(),
      diff_sat.to_sat(),
      diff_sat.to_btc(),
      utxo_id,
      changed_amount_sat.to_sat()
    );
    let to_addr_str = "bcrt1qy7wwnkflgl94asjv93cvusxy4chqpxlvrq7sa0"; //"2N5ZRwT42rHFjAtizZPa3Rp7Tn88PcoSzEB";//"n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";
    let to_addr = bitcoin::Address::from_str(to_addr_str).unwrap();
    let mut vin_alt_list = Vec::new();
    let mut txsource_list = Vec::new();
    for one_txin in txin_list_complete.iter() {
        let one_transaction = self.rpc
            .get_raw_transaction(&one_txin.txid, None, None)
            .await
            .unwrap();
        txsource_list.push(one_transaction.output[one_txin.vout as usize].clone());

        vin_alt_list.push(bitcoin::blockdata::transaction::TxIn {
            previous_output: 
            bitcoin::OutPoint {
                txid: one_txin.txid,
                vout: one_txin.vout,
            },
            script_sig: bitcoin::Script::new(),
            sequence: bitcoin::Sequence(u32::MAX),
            witness: bitcoin::Witness::default(),
        });
    }

    let mut vout_alt_list = Vec::new();
    if changed_amount_sat.to_sat() > 0 {
        vout_alt_list.push(bitcoin::TxOut {
            value: changed_amount_sat.to_sat(),
            script_pubkey: from_addr.script_pubkey(),
        });
    }
    vout_alt_list.push(bitcoin::TxOut {
        value: send_amount_sat.to_sat(),
        script_pubkey: to_addr.script_pubkey(),
    });

    let new_transaction = bitcoin::blockdata::transaction::Transaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vin_alt_list,
        output: vout_alt_list,
    };
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(new_transaction).unwrap();
    //dbg!(psbt);
    for (i, one_txinout) in txsource_list.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(one_txinout.clone());
        //psbt.inputs[0].redeem_script = Some(from_addr.script_pubkey());
        //psbt.inputs[i].tap_key_sig = 
    }

    let (tap_sighash, _schnorr_sighash_type) = taproot_sighash(&psbt, 0).unwrap();
    dbg!(&tap_sighash);

  }
}
