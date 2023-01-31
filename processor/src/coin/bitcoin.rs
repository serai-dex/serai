use std::io;

use async_trait::async_trait;

use bitcoin::{
  hashes::Hash,
  schnorr::TweakedPublicKey,
  XOnlyPublicKey, SchnorrSighashType,
  consensus::encode,
  util::address::Address,
  psbt::{PartiallySignedTransaction, PsbtSighashType},
  OutPoint, BlockHash, Block,
};

use transcript::RecommendedTranscript;
use k256::{
  ProjectivePoint, Scalar,
  elliptic_curve::sec1::{ToEncodedPoint, Tag},
};
use frost::{curve::Secp256k1, ThresholdKeys};

use bitcoin_serai::{
  rpc::Rpc,
  crypto::make_even,
  SpendableOutput,
  transactions::{TransactionMachine, SignableTransaction as BSignableTransaction},
};

use crate::coin::{CoinError, Block as BlockTrait, OutputType, Output as OutputTrait, Coin};

impl BlockTrait for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.block_hash().as_hash().into_inner()
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64,
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    self.per_weight * u64::try_from(weight).unwrap()
  }
}

#[derive(Clone, Debug)]
pub struct Output(BlockHash, SpendableOutput);
impl OutputTrait for Output {
  type Id = [u8; 36];

  // TODO: Implement later
  fn kind(&self) -> OutputType {
    OutputType::External
  }

  fn id(&self) -> Self::Id {
    encode::serialize(&self.1.output).try_into().unwrap()
  }

  fn amount(&self) -> u64 {
    self.1.amount
  }

  fn serialize(&self) -> Vec<u8> {
    let mut res = self.0.as_hash().into_inner().to_vec();
    res.append(&mut self.1.serialize());
    res
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut hash = [0; 32];
    reader.read_exact(&mut hash)?;
    Ok(Output(BlockHash::from_hash(Hash::from_inner(hash)), SpendableOutput::read(reader)?))
  }
}

#[derive(Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Secp256k1>,
  transcript: RecommendedTranscript,
  actual: BSignableTransaction,
}

#[derive(Clone, Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Rpc,
}
impl Bitcoin {
  pub async fn new(url: String) -> Bitcoin {
    Bitcoin { rpc: Rpc::new(url) }
  }

  #[cfg(test)]
  pub async fn fresh_chain(&self) {
    if self.rpc.get_latest_block_number().await.unwrap() > 0 {
      self
        .rpc
        .rpc_call("invalidateblock", serde_json::json!([self.rpc.get_block_hash(1).await.unwrap()]))
        .await
        .unwrap()
    }
  }

  #[cfg(test)]
  fn test_address_with_key() -> (bitcoin::PrivateKey, bitcoin::PublicKey, Address) {
    use bitcoin::{PrivateKey, PublicKey, Network};
    use secp256k1::{rand, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let private_key = PrivateKey::new(secret_key, Network::Regtest);
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    let address = Address::p2pkh(&public_key, Network::Regtest);
    (private_key, public_key, address)
  }
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
    debug_assert!(key.to_encoded_point(true).tag() == Tag::CompressedEvenY, "YKey is odd");
    let xonly_pubkey =
      XOnlyPublicKey::from_slice(key.to_encoded_point(true).x().to_owned().unwrap()).unwrap();
    let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(xonly_pubkey);
    Address::p2tr_tweaked(tweaked_pubkey, bitcoin::Network::Regtest)
  }

  // TODO: Implement later
  fn branch_address(&self, key: ProjectivePoint) -> Self::Address {
    self.address(key)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    Ok(self.rpc.get_latest_block_number().await.map_err(|_| CoinError::ConnectionError)?)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let block_hash =
      self.rpc.get_block_hash(number).await.map_err(|_| CoinError::ConnectionError)?;
    self.rpc.get_block(&block_hash).await.map_err(|_| CoinError::ConnectionError)
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: ProjectivePoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let main_addr = self.address(key);

    let mut outputs = Vec::new();
    // Skip the coinbase transaction which is burdened by maturity
    for tx in &block.txdata[1 ..] {
      for (vout, output) in tx.output.iter().enumerate() {
        if output.script_pubkey == main_addr.script_pubkey() {
          outputs.push(Output(
            block.block_hash(),
            SpendableOutput {
              output: OutPoint { txid: tx.txid(), vout: u32::try_from(vout).unwrap() },
              amount: output.value,
            },
          ));
        }
      }
    }

    Ok(outputs)
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Secp256k1>,
    transcript: RecommendedTranscript,
    _: usize,
    inputs: Vec<Output>,
    payments: &[(Address, u64)],
    change: Option<ProjectivePoint>,
    fee: Fee,
  ) -> Result<Self::SignableTransaction, CoinError> {
    let mut vin_alt_list = Vec::new();
    let mut vout_alt_list = Vec::new();
    let change = change.map(|change| self.address(change));

    let mut input_sat = 0;
    for one_input in &inputs {
      input_sat += one_input.amount();
      vin_alt_list.push(bitcoin::blockdata::transaction::TxIn {
        previous_output: one_input.1.output,
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

    let mut actual_fee = fee
      .calculate(BSignableTransaction::calculate_weight(vin_alt_list.len(), payments, false) * 2);
    if payment_sat > input_sat - actual_fee {
      return Err(CoinError::NotEnoughFunds);
    } else if input_sat != payment_sat {
      actual_fee = fee
        .calculate(BSignableTransaction::calculate_weight(vin_alt_list.len(), payments, true) * 2);
      // TODO: we need to drop outputs worth less than payment_sat
      if payment_sat < (input_sat - actual_fee) {
        let rest_sat = input_sat - actual_fee - payment_sat;
        if let Some(change) = change {
          vout_alt_list
            .push(bitcoin::TxOut { value: rest_sat, script_pubkey: change.script_pubkey() });
        }
      }
    }

    let new_transaction = bitcoin::blockdata::transaction::Transaction {
      version: 2,
      lock_time: bitcoin::PackedLockTime(0),
      input: vin_alt_list,
      output: vout_alt_list,
    };
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(new_transaction.clone()).unwrap();
    for (i, one_input) in inputs.iter().enumerate() {
      let one_transaction =
        self.rpc.get_transaction(&one_input.0, &one_input.1.output.txid).await.unwrap();
      let xonly_pubkey =
        XOnlyPublicKey::from_slice(keys.group_key().to_encoded_point(true).x().to_owned().unwrap())
          .unwrap();
      psbt.inputs[i].witness_utxo =
        Some(one_transaction.output[usize::try_from(one_input.1.output.vout).unwrap()].clone());
      psbt.inputs[i].sighash_type = Some(PsbtSighashType::from(SchnorrSighashType::All));
      psbt.inputs[i].tap_internal_key = Some(xonly_pubkey);
    }
    return Ok(SignableTransaction {
      keys,
      transcript,
      actual: BSignableTransaction { tx: psbt, fee: actual_fee },
    });
  }

  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError> {
    transaction
      .actual
      .clone()
      .multisig(transaction.keys.clone(), transaction.transcript.clone())
      .await
      .map_err(|_| CoinError::ConnectionError)
  }

  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, CoinError> {
    let target_tx = tx.clone().extract_tx();
    let s_raw_transaction = self.rpc.send_raw_transaction(&target_tx).await.unwrap();
    Ok(s_raw_transaction.to_vec())
  }

  fn tweak_keys(&self, key: &mut ThresholdKeys<Self::Curve>) {
    if key.group_key().to_encoded_point(true).tag() == Tag::CompressedEvenY {
      return;
    }
    let (_, offset) = make_even(key.group_key());
    *key = key.offset(Scalar::from(offset));
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    // TODO: Add fee estimation (42 satoshi / byte)
    Self::Fee { per_weight: 11 }
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    use bitcoin::{
      Address, PrivateKey, PublicKey, Network,
      secp256k1::{SecretKey, rand, Secp256k1},
    };

    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let private_key = PrivateKey::new(secret_key, Network::Regtest);
    let public_key = PublicKey::from_private_key(&secp, &private_key);

    let new_addr = Address::p2wpkh(&public_key, Network::Regtest).unwrap();
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, new_addr.to_string()]))
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    use bitcoin::{
      OutPoint, Sequence, Witness, Script, PackedLockTime,
      blockdata::{
        script::Builder,
        transaction::{TxIn, TxOut, Transaction},
      },
      secp256k1::{Secp256k1, Message},
    };

    let (private_key, public_key, main_addr) = Self::test_address_with_key();
    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr.to_string()]))
      .await
      .unwrap();

    for _ in 0 .. 100 {
      self.mine_block().await;
    }

    let tx = self.get_block(new_block).await.unwrap().txdata.swap_remove(0);
    let mut tx = Transaction {
      version: 2,
      lock_time: PackedLockTime(0),
      input: vec![TxIn {
        previous_output: OutPoint { txid: tx.txid(), vout: 0 },
        script_sig: Script::default(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
      }],
      output: vec![TxOut {
        value: tx.output[0].value - 10000,
        script_pubkey: address.script_pubkey(),
      }],
    };

    let secp = Secp256k1::new();
    let transactions_sighash = tx.signature_hash(0, &main_addr.script_pubkey(), 1);
    let mut signed_der = secp
      .sign_ecdsa_low_r(&Message::from(transactions_sighash.as_hash()), &private_key.inner)
      .serialize_der()
      .to_vec();
    signed_der.push(1);
    tx.input[0].script_sig =
      Builder::new().push_slice(&signed_der).push_key(&public_key).into_script();

    self.rpc.send_raw_transaction(&tx).await.unwrap();
    for _ in 0 .. 3 {
      self.mine_block().await;
    }
  }
}
