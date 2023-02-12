use std::{io, collections::HashMap};

use async_trait::async_trait;

use bitcoin::{
  hashes::Hash as HashTrait, schnorr::TweakedPublicKey, psbt::serialize::Serialize, OutPoint,
  Transaction, Block, Network, Address as BAddress,
};

#[cfg(test)]
use bitcoin::{
  hashes::sha256d::Hash,
  secp256k1::{SECP256K1, SecretKey, Message},
  PrivateKey, PublicKey, EcdsaSighashType,
  blockdata::script::Builder,
  PackedLockTime, Sequence, Script, Witness, TxIn, TxOut, BlockHash,
};

use transcript::RecommendedTranscript;
use k256::{
  ProjectivePoint, Scalar,
  elliptic_curve::sec1::{ToEncodedPoint, Tag},
};
use frost::{curve::Secp256k1, ThresholdKeys};

use bitcoin_serai::{
  crypto::{x_only, make_even},
  wallet::{SpendableOutput, TransactionMachine, SignableTransaction as BSignableTransaction},
  rpc::{RpcError, Rpc},
};

use crate::{
  coin::{
    CoinError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, Coin,
  },
  Plan,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputId(pub [u8; 36]);
impl Default for OutputId {
  fn default() -> Self {
    Self([0; 36])
  }
}
impl AsRef<[u8]> for OutputId {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl AsMut<[u8]> for OutputId {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  kind: OutputType,
  output: SpendableOutput,
  data: Vec<u8>,
}

impl OutputTrait for Output {
  type Id = OutputId;

  fn kind(&self) -> OutputType {
    self.kind
  }

  fn id(&self) -> Self::Id {
    OutputId(self.output.id())
  }

  fn amount(&self) -> u64 {
    self.output.output.value
  }

  fn data(&self) -> &[u8] {
    todo!()
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.kind.write(writer)?;
    self.output.write(writer)?;
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Ok(Output {
      kind: OutputType::read(reader)?,
      output: SpendableOutput::read(reader)?,
      data: {
        let mut data_len = [0; 2];
        reader.read_exact(&mut data_len)?;

        let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
        reader.read_exact(&mut data)?;
        data
      },
    })
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee(u64);

impl TransactionTrait for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.txid().as_hash().into_inner()
  }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Secp256k1>,
  transcript: RecommendedTranscript,
  actual: BSignableTransaction,
}
impl PartialEq for SignableTransaction {
  fn eq(&self, other: &SignableTransaction) -> bool {
    self.actual == other.actual
  }
}
impl Eq for SignableTransaction {}

impl BlockTrait<Bitcoin> for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.block_hash().as_hash().into_inner()
  }
  fn median_fee(&self) -> Fee {
    // TODO
    Fee(20)
  }
}

fn next_key(mut key: ProjectivePoint, i: usize) -> (ProjectivePoint, Scalar) {
  let mut offset = Scalar::ZERO;
  for _ in 0 .. i {
    key += ProjectivePoint::GENERATOR;
    offset += Scalar::ONE;

    let even_offset;
    (key, even_offset) = make_even(key);
    offset += Scalar::from(even_offset);
  }
  (key, offset)
}

fn branch(key: ProjectivePoint) -> (ProjectivePoint, Scalar) {
  next_key(key, 1)
}

fn change(key: ProjectivePoint) -> (ProjectivePoint, Scalar) {
  next_key(key, 2)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(BAddress);
impl ToString for Address {
  fn to_string(&self) -> String {
    self.0.to_string()
  }
}
impl TryFrom<Vec<u8>> for Address {
  type Error = ();
  fn try_from(data: Vec<u8>) -> Result<Address, ()> {
    todo!();
  }
}

#[derive(Clone, Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Rpc,
}
// Shim required for testing/debugging purposes due to generic arguments also necessitating trait
// bounds
impl PartialEq for Bitcoin {
  fn eq(&self, _: &Self) -> bool {
    true
  }
}
impl Eq for Bitcoin {}

impl Bitcoin {
  pub fn new(url: String) -> Bitcoin {
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
}

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction = Transaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = Address;

  const ID: &'static str = "Bitcoin";
  const CONFIRMATIONS: usize = 3;

  // Bitcoin has a max weight of 400,000 (MAX_STANDARD_TX_WEIGHT)
  // A non-SegWit TX will have 4 weight units per byte, leaving a max size of 100,000 bytes
  // While our inputs are entirely SegWit, such fine tuning is not necessary and could create
  // issues in the future (if the size decreases or we mis-evaluate it)
  // It also offers a minimal amount of benefit when we are able to logarithmically accumulate
  // inputs
  // For 128-byte inputs (40-byte output specification, 64-byte signature, whatever overhead) and
  // 64-byte outputs (40-byte script, 8-byte amount, whatever overhead), they together take up 192
  // bytes
  // 100,000 / 192 = 520
  // 520 * 192 leaves 160 bytes of overhead for the transaction structure itself
  const MAX_INPUTS: usize = 520;
  const MAX_OUTPUTS: usize = 520;

  fn tweak_keys(key: &mut ThresholdKeys<Self::Curve>) {
    let (_, offset) = make_even(key.group_key());
    *key = key.offset(Scalar::from(offset));
  }

  fn address(key: ProjectivePoint) -> Self::Address {
    debug_assert!(key.to_encoded_point(true).tag() == Tag::CompressedEvenY, "YKey is odd");
    Address(BAddress::p2tr_tweaked(
      TweakedPublicKey::dangerous_assume_tweaked(x_only(&key)),
      Network::Regtest,
    ))
  }

  fn branch_address(key: ProjectivePoint) -> Self::Address {
    Self::address(branch(key).0)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    self.rpc.get_latest_block_number().await.map_err(|_| CoinError::ConnectionError)
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
    let external = (key, Scalar::ZERO);
    let branch = branch(key);
    let change = change(key);

    let entry =
      |pair: (_, _), kind| (Self::address(pair.0).0.script_pubkey().to_bytes(), (pair.1, kind));
    let scripts = HashMap::from([
      entry(external, OutputType::External),
      entry(branch, OutputType::Branch),
      entry(change, OutputType::Change),
    ]);

    let mut outputs = Vec::new();
    // Skip the coinbase transaction which is burdened by maturity
    for tx in &block.txdata[1 ..] {
      for (vout, output) in tx.output.iter().enumerate() {
        if let Some(info) = scripts.get(&output.script_pubkey.to_bytes()) {
          outputs.push(Output {
            kind: info.1,
            output: SpendableOutput {
              offset: info.0,
              output: output.clone(),
              outpoint: OutPoint { txid: tx.txid(), vout: u32::try_from(vout).unwrap() },
            },
            data: {
              let last = tx.output.last().unwrap();
              Some(last.script_pubkey.to_bytes()[1 ..].to_vec())
                .filter(|_| last.script_pubkey.is_op_return())
                .unwrap_or(vec![])
            },
          });
        }
      }
    }

    Ok(outputs)
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Secp256k1>,
    _: usize,
    mut tx: Plan<Self>,
    fee: Fee,
  ) -> Result<Self::SignableTransaction, CoinError> {
    Ok(SignableTransaction {
      keys,
      transcript: tx.transcript(),
      actual: BSignableTransaction::new(
        tx.inputs.drain(..).map(|input| input.output).collect(),
        &tx
          .payments
          .drain(..)
          .map(|payment| (payment.address.0, payment.amount))
          .collect::<Vec<_>>(),
        tx.change.map(|key| Self::address(change(key).0).0),
        None,
        fee.0,
      )
      .unwrap(),
    })
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

  fn serialize_transaction(tx: &Self::Transaction) -> Vec<u8> {
    tx.serialize()
  }

  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<(), CoinError> {
    match self.rpc.send_raw_transaction(tx).await {
      Ok(_) => (),
      Err(RpcError::ConnectionError) => Err(CoinError::ConnectionError)?,
      // TODO: Distinguish already in pool vs invalid transaction
      Err(e) => panic!("failed to publish TX {:?}: {e}", tx.txid()),
    }
    Ok(())
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> Result<usize, CoinError> {
    self
      .rpc
      .get_block_number(&BlockHash::from_hash(Hash::from_inner(*id)))
      .await
      .map_err(|_| CoinError::ConnectionError)
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    Fee(1)
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    self
      .rpc
      .rpc_call::<Vec<String>>(
        "generatetoaddress",
        serde_json::json!([
          1,
          BAddress::p2sh(&Script::new(), Network::Regtest).unwrap().to_string()
        ]),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) -> Block {
    let secret_key = SecretKey::new(&mut rand_core::OsRng);
    let private_key = PrivateKey::new(secret_key, Network::Regtest);
    let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
    let main_addr = BAddress::p2pkh(&public_key, Network::Regtest);

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr]))
      .await
      .unwrap();

    for _ in 0 .. 100 {
      self.mine_block().await;
    }

    // TODO: Consider grabbing bdk as a dev dependency
    let tx = self.get_block(new_block).await.unwrap().txdata.swap_remove(0);
    let mut tx = Transaction {
      version: 2,
      lock_time: PackedLockTime::ZERO,
      input: vec![TxIn {
        previous_output: OutPoint { txid: tx.txid(), vout: 0 },
        script_sig: Script::default(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
      }],
      output: vec![TxOut {
        value: tx.output[0].value - 10000,
        script_pubkey: address.0.script_pubkey(),
      }],
    };

    let mut der = SECP256K1
      .sign_ecdsa_low_r(
        &Message::from(
          tx.signature_hash(0, &main_addr.script_pubkey(), EcdsaSighashType::All.to_u32())
            .as_hash(),
        ),
        &private_key.inner,
      )
      .serialize_der()
      .to_vec();
    der.push(1);
    tx.input[0].script_sig = Builder::new().push_slice(&der).push_key(&public_key).into_script();

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.send_raw_transaction(&tx).await.unwrap();
    for _ in 0 .. Self::CONFIRMATIONS {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}
