use async_trait::async_trait;
use bitcoin_hashes::hex::{FromHex, ToHex};
use std::str::FromStr;
use transcript::RecommendedTranscript;

use frost::{
  curve::Secp256k1,
  ThresholdKeys,
};

use bitcoin::{
  Block as BBlock,
  util::address::Address,
  Txid, schnorr::TweakedPublicKey,
  XOnlyPublicKey, SchnorrSighashType,
  psbt::{PartiallySignedTransaction,PsbtSighashType},
};

use bitcoin_serai::{
  rpc::Rpc,
  rpc_helper::RawTx,
  crypto::make_even,
  wallet::SpendableOutput,
  transactions::{TransactionMachine, SignableTransaction as BSignableTransaction},
};

use k256::{
  ProjectivePoint, Scalar,
  elliptic_curve::sec1::{ToEncodedPoint, Tag},
};
use crate::{
  coin::{CoinError, Block as BlockTrait, OutputType, Output as OutputTrait, Coin}
};

#[derive(Clone, Debug)]
pub struct Block([u8; 32], BBlock);
impl BlockTrait for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.0
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    ((self.per_weight * u64::try_from(weight).unwrap()) - 1) 
  }
}

#[derive(Clone, Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Rpc,
  
}
impl Bitcoin {
  pub async fn new(url: String, username: Option<String>, userpass: Option<String>) -> Bitcoin {
    Bitcoin { rpc: Rpc::new(url, username.unwrap(), userpass.unwrap()).unwrap()}
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
  type Id = [u8; 36];

  //TODO: Implement later
  fn kind(&self) -> OutputType {
    OutputType::External
  }

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

  fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    SpendableOutput::read(reader).map(Output)
  }
}

#[derive(Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Secp256k1>,
  transcript: RecommendedTranscript,
  height: usize,
  actual: BSignableTransaction,
}

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction = PartiallySignedTransaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 3;

  // TODO: Get hard numbers and tune
  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: ProjectivePoint) -> Self::Address {
    assert!(key.to_encoded_point(true).tag() == Tag::CompressedEvenY, "YKey is odd");
    let xonly_pubkey =
      XOnlyPublicKey::from_slice(&key.to_encoded_point(true).x().to_owned().unwrap()).unwrap();
    let tweaked_pubkey = bitcoin::schnorr::TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    Address::p2tr_tweaked(tweaked_pubkey, bitcoin::network::constants::Network::Regtest)
  }

  //TODO: Implement later
  fn branch_address(&self, key: ProjectivePoint) -> Self::Address {
    self.address(key)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    Ok(self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)?)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let block_hash = self.rpc.get_block_hash(number - 1).await.unwrap();
    let info = self.rpc.get_block(&block_hash).await.unwrap();
    let BBlock = Block(info.block_hash().to_vec()[0..32].try_into().unwrap(),info);
    Ok(BBlock)
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: ProjectivePoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let main_addr = self.address(key);
    let block_details = self.rpc.get_block_with_transactions(&block.1.block_hash()).await.unwrap();
    let mut outputs = Vec::new();
    for one_transaction in block_details.tx {
      for output_tx in one_transaction.vout {
        if output_tx.script_pub_key.script().unwrap().cmp(&main_addr.script_pubkey()).is_eq() {
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
    change: Option<ProjectivePoint>,
    fee: Fee,
  ) -> Result<Self::SignableTransaction, CoinError> {
    let mut vin_alt_list = Vec::new();
    let mut vout_alt_list = Vec::new();
    let change_addr = self.address(change.unwrap());

    let mut input_sat = 0;
    for one_input in &inputs {
      input_sat += one_input.amount();
      vin_alt_list.push(bitcoin::blockdata::transaction::TxIn {
        previous_output: bitcoin::OutPoint { txid: one_input.0.txid, vout: one_input.0.vout },
        script_sig: bitcoin::Script::new(),
        sequence: bitcoin::Sequence(u32::MAX),
        witness: bitcoin::Witness::default(),
      });
    }

    let mut payment_sat = 0;
    for one_payment in payments {
      payment_sat += one_payment.1;
      vout_alt_list.push(bitcoin::TxOut {
        value: one_payment.1,
        script_pubkey: one_payment.0.script_pubkey(),
      });
    }

    let transaction_weight = BSignableTransaction::calculate_weight(vin_alt_list.len(), &payments[0].0, false);
    let mut actual_fee = fee.calculate(transaction_weight);
    let target_sat = actual_fee + payment_sat;
    if input_sat < target_sat {
      //TODO: Change it with TransactionError
      return Err(CoinError::ConnectionError);
    }
    else if input_sat != target_sat {
      let transaction_weight = BSignableTransaction::calculate_weight(vin_alt_list.len(), &payments[0].0, true);
      actual_fee = fee.calculate(transaction_weight);
      let target_sat = actual_fee + payment_sat;
      if target_sat < input_sat {
        let rest_sat = input_sat - target_sat;
        vout_alt_list.push(bitcoin::TxOut {
          value: rest_sat,
          script_pubkey: change_addr.script_pubkey(),
        });
      }
    }

    let new_transaction = bitcoin::blockdata::transaction::Transaction {
      version: 2,
      lock_time: bitcoin::PackedLockTime(0),
      input: vin_alt_list,
      output: vout_alt_list,
    };
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(new_transaction.clone()).unwrap();
    for (i, one_input) in (&inputs).iter().enumerate() {
      let one_transaction = self.rpc.get_raw_transaction(&one_input.0.txid, None, None).await.unwrap();
      let xonly_pubkey = XOnlyPublicKey::from_slice(&keys.group_key().to_encoded_point(true).x().to_owned().unwrap()).unwrap();
      psbt.inputs[i].witness_utxo = Some(one_transaction.output[usize::try_from(one_input.0.vout).unwrap()].clone());
      psbt.inputs[i].sighash_type = Some(PsbtSighashType::from(SchnorrSighashType::All));
      psbt.inputs[i].tap_internal_key = Some(xonly_pubkey);
    }
    return Ok(SignableTransaction { keys: keys, transcript: transcript, height: block_number+1, actual: BSignableTransaction{tx: psbt, fee:actual_fee} });
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
    let s_raw_transaction = self.rpc.send_raw_str_transaction(target_tx.raw_hex()).await.unwrap();
    let vec_output = target_tx
      .output
      .iter()
      .enumerate()
      .map(|(i, output)| {
        let one_output = SpendableOutput {
          txid: Txid::from_str(target_tx.txid().to_string().as_str()).unwrap(),
          amount: output.value,
          vout: u32::try_from(i).unwrap(),
        };
        Output(one_output).id()
      })
      .collect();
    Ok((s_raw_transaction.to_vec(), vec_output))
  }

  fn tweak_keys<'a>(&self, key: &'a mut ThresholdKeys<Self::Curve>) {
    if key.group_key().to_encoded_point(true).tag() == Tag::CompressedEvenY {
      return;
    }
    let (_, offset) = make_even(key.group_key());
    *key = key.offset(Scalar::from(offset));
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    //TODO: Add fee estimation (42 satoshi / byte)
    Self::Fee { per_weight: 11 }
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    use bitcoincore_rpc_json::{AddressType};

    let new_addr = self.rpc.get_new_address(None, Some(AddressType::Bech32)).await.unwrap();
    self.rpc.generate_to_address(1, new_addr.to_string().as_str()).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    use bitcoin::{schnorr::SchnorrSig, psbt::serialize::Serialize};
    use bitcoin_serai::crypto::{BitcoinHram, taproot_key_spend_signature_hash};
    use frost::{algorithm::Schnorr, tests::{algorithm_machines, key_gen, sign}};
    use rand_core::OsRng;
    use transcript::Transcript;

    let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
    for (_, key) in keys.iter_mut() {
      self.tweak_keys(key);
    }
    let key = keys[&1].group_key();
    let one_key = keys[&1].clone();

    let change_address = self.address(key);
    let new_block = self.get_latest_block_number().await.unwrap() + 1;

    self.rpc.generate_to_address(1, change_address.to_string().as_str()).await.unwrap();
    self.rpc.generate_to_address(2, address.to_string().as_str()).await.unwrap();
    for _ in 0..100 {
      self.mine_block().await;
    }

    let block_number = new_block + 1;
    let active_block = self.get_block(block_number).await.unwrap();
    let inputs = self.get_outputs(&active_block, key).await.unwrap();

    let amount = inputs[0].amount();
    let change_amount = 10000;
    let fee = Self::Fee { per_weight: 42 };
    let transaction_weight = BSignableTransaction::calculate_weight(inputs.len(), &address, false);
    let total_amount = amount - fee.calculate(transaction_weight) - change_amount;
    let transcript = RecommendedTranscript::new(b"bitcoin_test");
    let payments = vec![(address, total_amount)];
    let mut signable_transactions = self.prepare_send(one_key, transcript, block_number, inputs, &payments, Some(key), fee).await.unwrap();
  
    for i in 0..signable_transactions.actual.tx.inputs.len() {
      let (tx_sighash, _) = taproot_key_spend_signature_hash(&signable_transactions.actual.tx, i).unwrap();
      let algo = Schnorr::<Secp256k1, BitcoinHram>::new();
      let mut _sig = sign(
        &mut OsRng,
        algo.clone(),
        keys.clone(),
        algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, BitcoinHram>::new(), &keys),
        &tx_sighash.as_ref(),
      );

      let mut _offset = 0;
      (_sig.R, _offset) = make_even(_sig.R);
      _sig.s += Scalar::from(_offset);

      let temp_sig = secp256k1::schnorr::Signature::from_slice(&_sig.serialize()[1..65]).unwrap();
      let sig = SchnorrSig { sig: temp_sig, hash_ty: SchnorrSighashType::All };
      signable_transactions.actual.tx.inputs[i].tap_key_sig = Some(sig);
      let mut script_witness: bitcoin::Witness = bitcoin::Witness::new();
      script_witness.push(signable_transactions.actual.tx.inputs[i].tap_key_sig.unwrap().serialize());
      signable_transactions.actual.tx.inputs[i].final_script_witness = Some(script_witness);
    }
    let _result = self.publish_transaction(&signable_transactions.actual.tx).await.unwrap();
  }
}
