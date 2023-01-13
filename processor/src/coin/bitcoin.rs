use std::{str::FromStr, collections::HashMap};

use async_trait::async_trait;

use transcript::RecommendedTranscript;
use frost::{
  curve::{Secp256k1},//Ciphersuite
  ThresholdKeys,
  tests::key_gen,
};

use rand_core::OsRng;

use bitcoin_hashes::hex::{FromHex, ToHex};

use bitcoin::{
  PrivateKey,
  util::address::Address,
  Txid,
  schnorr::{TweakedPublicKey, SchnorrSig},
  XOnlyPublicKey,
  psbt::{PartiallySignedTransaction,PsbtSighashType},
  SchnorrSighashType,
};

use bitcoin_serai::{
  rpc::Rpc,
  rpc_helper::RawTx,
  crypto::{make_even},
  wallet::{SpendableOutput},
  transactions::{TransactionMachine,SignableTransaction as MSignableTransaction},
};

use bitcoincore_rpc_json::{AddressType, ListUnspentResultEntry};

use k256::{
  ProjectivePoint, Scalar,
  elliptic_curve::{
    sec1::{ToEncodedPoint, Tag},
  },
};
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
  pub async fn new(url: String, username: Option<String>, userpass: Option<String>) -> Bitcoin {
    Bitcoin { rpc: Rpc::new(url, username.unwrap(), userpass.unwrap()).unwrap() }
  }
}

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
    let ret: [u8; 36] = serialized_data[0..36].try_into().unwrap();
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

#[derive(Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Secp256k1>,
  transcript: RecommendedTranscript,
  // Monero height, defined as the length of the chain
  height: usize,
  actual: MSignableTransaction,
}

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction = PartiallySignedTransaction; //bitcoin::Transaction;
  type Block = bitcoin::Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 3;

  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: ProjectivePoint) -> Self::Address {
    assert!(key.to_encoded_point(true).tag() == Tag::CompressedEvenY, "YKey is odd");
    let xonly_pubkey =
      XOnlyPublicKey::from_slice(&key.to_encoded_point(true).x().to_owned().unwrap()).unwrap();

    let tweaked_pubkey = bitcoin::schnorr::TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    let result_addr = Address::p2tr_tweaked(tweaked_pubkey, bitcoin::network::constants::Network::Regtest);
    result_addr
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
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
    let tx_block_number =
      self.rpc.get_transaction_block_number(&txid_str.to_string()).await.unwrap();
    Ok((self.get_latest_block_number().await.unwrap().saturating_sub(tx_block_number) + 1) >= 10)
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: ProjectivePoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let main_addr = self.address(key);
    self.rpc.generate_to_address(1, main_addr.to_string().as_str()).await.unwrap();
    let block_details = self.rpc.get_block_with_transactions(&block.block_hash()).await.unwrap();
    let mut outputs = Vec::new();
    for one_transaction in block_details.tx {
      for output_tx in one_transaction.vout {
        if output_tx.script_pub_key.script().unwrap().cmp(&main_addr.script_pubkey()).is_eq() {
          println!("It is spendable {}",output_tx.value.to_sat());
          outputs.push(Output(SpendableOutput {
            txid: one_transaction.txid,
            vout: output_tx.n,
            amount: output_tx.value.to_sat(),
          }));
        }
      }
    }
    return Ok(outputs);
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Secp256k1>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut inputs: Vec<Output>,
    payments: &[(Address, u64)],
    fee: Fee,
  ) -> Result<Self::SignableTransaction, CoinError> {
    dbg!("prepare_send from bitcoin called");
    let mut vin_alt_list = Vec::new();
    let mut vout_alt_list = Vec::new();

    for one_payment in payments {
      vout_alt_list.push(bitcoin::TxOut {
        value: one_payment.1,
        script_pubkey: one_payment.0.script_pubkey(),
      });
    }

    for one_input in &inputs {
      vin_alt_list.push(bitcoin::blockdata::transaction::TxIn {
        previous_output: bitcoin::OutPoint { txid: one_input.0.txid, vout: one_input.0.vout },
        script_sig: bitcoin::Script::new(),
        sequence: bitcoin::Sequence(u32::MAX),
        witness: bitcoin::Witness::default(),
      });
    }

    let new_transaction = bitcoin::blockdata::transaction::Transaction {
      version: 2,
      lock_time: bitcoin::PackedLockTime(0),
      input: vin_alt_list,
      output: vout_alt_list,
    };

    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(new_transaction.clone()).unwrap();

    for (i, one_input) in (&inputs).iter().enumerate() {
      let txid = one_input.0.txid.clone();
      let one_transaction = self.rpc.get_raw_transaction(&txid, None, None).await.unwrap();
      let xonly_pubkey = XOnlyPublicKey::from_slice(&keys.group_key().to_encoded_point(true).x().to_owned().unwrap()).unwrap();
      psbt.inputs[i].witness_utxo = Some(one_transaction.output[one_input.0.vout as usize].clone());
      psbt.inputs[i].sighash_type = Some(PsbtSighashType::from_u32(SchnorrSighashType::All as u32));
      psbt.inputs[i].tap_internal_key = Some(xonly_pubkey);
    }
    return Ok(SignableTransaction { keys: keys, transcript: transcript, height: block_number+1, actual: MSignableTransaction{tx: psbt} });
  }

  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError> {
    transaction
    .actual
    .clone()
    .multisig(
      transaction.keys.clone(),
      transaction.transcript.clone(),
      transaction.height,
    )
    .await
    .map_err(|_| CoinError::ConnectionError)
  }

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    let target_tx = tx.clone().extract_tx();
    dbg!(&target_tx.raw_hex());

    let psbt_hex =  tx.clone().extract_tx().raw_hex();
    let test_transaction = self.rpc.test_mempool_accept(&[psbt_hex]).await.unwrap();
    dbg!(&test_transaction);

    let s_raw_transaction = self.rpc.send_raw_str_transaction(target_tx.raw_hex()).await.unwrap();
    let vec_output = target_tx
      .output
      .iter()
      .enumerate()
      .map(|(i, output)| {
        let one_output = SpendableOutput {
          txid: Txid::from_str(target_tx.txid().to_string().as_str()).unwrap(),
          amount: output.value,
          vout: i as u32,
        };
        Output(one_output).id()
      })
      .collect();
    Ok((s_raw_transaction.to_vec(), vec_output))
  }

  fn tweak_keys<'a>(&self, keys: &'a mut HashMap<u16, ThresholdKeys<Self::Curve>>) {
    for (_, one_key) in keys.iter_mut() {
      if one_key.group_key().to_encoded_point(true).tag() == Tag::CompressedEvenY {
        continue;
      }
      let (_, offset) = make_even(one_key.group_key());
      *one_key = one_key.offset(Scalar::from(offset));
    }
  }

  fn tweak_key<'a>(&self, one_key: &'a mut ThresholdKeys<Self::Curve>) {
    if one_key.group_key().to_encoded_point(true).tag() == Tag::CompressedEvenY {
      return;
    }
    let (_, offset) = make_even(one_key.group_key());
    *one_key = one_key.offset(Scalar::from(offset));
  }

  #[cfg(test)] //42 satoshi / byte
  async fn get_fee(&self) -> Self::Fee {
    Self::Fee { per_weight: 42, mask: 66 }
  }

  #[cfg(test)]
  async fn mine_block(&self, key: Option<ProjectivePoint>, count: Option<usize>) {
    dbg!("mine_block called");
    let mut new_addr = None;
    if key.is_some() {
      new_addr = Some(self.address(key.unwrap()));
    }
    else {
      new_addr = Some(self.rpc.get_new_address(None, Some(AddressType::Bech32)).await.unwrap());
    }

    let mut number_of_block = 1;
    if count.is_some() {
      number_of_block = count.unwrap();
    }
    
    self.rpc.generate_to_address(number_of_block, new_addr.unwrap().to_string().as_str()).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    dbg!("Bitcoin test send");
    /*let address_str = String::from("bcrt1q7kc7tm3a4qljpw4gg5w73cgya6g9nfydtessgs"); //new_addr.to_string();
    let from_addr = Address::from_str(address_str.as_str()).unwrap();

    let privkey_obj =
      PrivateKey::from_wif("cV9X6E3J9jq7R1XR8uPED2JqFxqcd6KrC8XWPy1GchZj7MA7G9Wx").unwrap();
    let pub1 = secp256k1::PublicKey::from_str(
      "02a3f8c9a120cfe9386f7bb9b85ecdade9c7b624441b346188913ab21584237672",
    )
    .unwrap();
    let secp = secp256k1::Secp256k1::new();

    let block_hash = self.rpc.get_block_hash(51).await.unwrap();
    let block = self.rpc.get_block(&block_hash).await.unwrap();

    let mut utxos = Vec::new();
    let block_details = self.rpc.get_block_with_transactions(&block.block_hash()).await.unwrap();
    //dbg!(&main_addr.script_pubkey());
    for one_transaction in block_details.tx {
      for output_tx in one_transaction.vout {
        //dbg!(&output_tx.script_pub_key.asm);
        //if output_tx.script_pub_key.script().unwrap().cmp(&main_addr.script_pubkey()).is_eq() {
        println!("It is spendable");
        utxos.push(Output(SpendableOutput {
          txid: one_transaction.txid,
          vout: output_tx.n,
          amount: output_tx.value.to_sat(),
        }));
        //}
      }
    }

    //let mut utxos = self.get_outputs(&block, &from_addr).await.unwrap();
    //dbg!(results);

    let mut txin_list_complete = Vec::new();

    let fee_amount_sat = bitcoin::Amount::from_sat(100000);
    let send_amount_sat = bitcoin::Amount::from_sat(2341521000);
    let total_amount_sat = fee_amount_sat.checked_add(send_amount_sat).unwrap();

    let mut sum_sat = bitcoin::Amount::from_sat(0);
    let mut diff_sat = bitcoin::Amount::from_sat(9999999999999);
    let mut temp_diff_sat = bitcoin::Amount::from_sat(0);
    let mut utxo_id = 0;
    let mut changed_amount_sat = bitcoin::Amount::from_sat(0);

    let it = utxos.iter();
    for (i, one_utx) in it.enumerate() {
      let amount = bitcoin::Amount::from_sat(one_utx.amount());
      if amount.checked_sub(total_amount_sat).is_some() {
        temp_diff_sat = amount.checked_sub(total_amount_sat).unwrap();
        if temp_diff_sat < diff_sat {
          diff_sat = temp_diff_sat;
          utxo_id = i + 1;

          changed_amount_sat = temp_diff_sat;
        }
      }

      sum_sat = sum_sat.checked_add(amount).unwrap();
    }

    if total_amount_sat > sum_sat {
      panic!("No way to reach that much of bitcoin to send !");
    }

    if utxo_id == 0 {
      println!("No utxo found - Total : {}", sum_sat.to_sat());
      utxos.sort_by(|k1, k2| k2.amount().cmp(&k1.amount()));
      sum_sat = bitcoin::Amount::from_sat(0);
      let it = utxos.iter();
      for (i, one_utx) in it.enumerate() {
        let amount = bitcoin::Amount::from_sat(one_utx.amount());
        sum_sat = sum_sat.checked_add(amount).unwrap();
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
    } else {
      txin_list_complete.push(&utxos[utxo_id - 1]);
    }

    println!(
      "Total Amount: {} Diff sat: {}  -  Diff Btc: {}, Best ID : {} Change:{}",
      total_amount_sat.to_btc(),
      diff_sat.to_sat(),
      diff_sat.to_btc(),
      utxo_id,
      changed_amount_sat.to_sat()
    );

    let to_addr = self.rpc.get_new_address(None, Some(AddressType::Bech32)).await.unwrap();
    let mut vin_alt_list = Vec::new();
    let mut txsource_list = Vec::new();
    for one_txin in txin_list_complete.iter() {
      let one_transaction =
        self.rpc.get_raw_transaction(&one_txin.0.txid, None, None).await.unwrap();
      txsource_list.push(one_transaction.output[one_txin.0.vout as usize].clone());

      vin_alt_list.push(bitcoin::blockdata::transaction::TxIn {
        previous_output: bitcoin::OutPoint { txid: one_txin.0.txid, vout: one_txin.0.vout },
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

      //sign_psbt_schnorr(&privkey_obj.inner, pub1.x_only_public_key().0,None,
      //&mut psbt.inputs[i],tap_sighash,SchnorrSighashType::All,&secp);
      //dbg!(&psbt.inputs[i].tap_key_sig);
    }*/
  }
}
