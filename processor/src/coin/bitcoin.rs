use std::{str::FromStr, collections::HashMap};

use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar as OtherScalar;

use dalek_ff_group as dfg;
use group::GroupEncoding;
use transcript::RecommendedTranscript;
use frost::{
  curve::{Ed25519, Curve, Ciphersuite},
  ThresholdKeys,
};

use monero_serai::{
  transaction::Transaction,
  wallet::{
    ViewPair, Scanner,
    address::{Network},
    SpendableOutput, SignableTransaction as MSignableTransaction, TransactionMachine,
  },
};

use bitcoincore_rpc::{
  bitcoin::{self, hashes::hex::FromHex},
  Auth, Client, RpcApi,
};
use bitcoin::util::address::Address;
use sha2::{Digest, Sha256};

use crate::{
  additional_key,
  coin::{CoinError, Output as OutputTrait, Coin},
};

use frost::{algorithm::Hram, curve::Secp256k1};
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, sec1::Tag},
  ProjectivePoint, U256, Scalar,
};

fn make_even(mut key: ProjectivePoint) -> (ProjectivePoint, u64) {
  let mut c = 0;
  while key.to_encoded_point(true).tag() == Tag::CompressedOddY {
    key += Secp256k1::generator();
    c += 1;
  }
  (key, c)
}

#[derive(Clone, Default)]
pub struct BitcoinHram {}

impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    //print_keys(&A, "4. Public Keys".to_string());
    //print_keys(&R, "1. R Keys".to_string());

    let (R,offset) = make_even(*R);
    dbg!(offset);
    
    //print_keys(&A, "5. Public Keys".to_string());
    //print_keys(&R, "2. R Keys".to_string());

    let r_encoded_point = R.to_encoded_point(true);
    let a_encoded_point = A.to_encoded_point(true);
    let mut data = Sha256::new();
    let tag = b"BIP0340/challenge";
    let tag_hash = Sha256::digest(tag);
    data.update(tag_hash);
    data.update(tag_hash);
    data.update(r_encoded_point.x().to_owned().unwrap());
    data.update(a_encoded_point.x().to_owned().unwrap()); //&a_encoded_point.to_owned().to_bytes()[1 ..]
    data.update(&m[..]);

    let res_data = data.finalize();
    let res = Scalar::from_uint_reduced(U256::from_be_slice(&res_data));
    return res;
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
  type Id = [u8; 32];

  fn id(&self) -> Self::Id {
    self.0.output.data.key.compress().to_bytes()
  }

  fn amount(&self) -> u64 {
    self.0.commitment().amount
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
  keys: ThresholdKeys<Ed25519>,
  transcript: RecommendedTranscript,
  // - height, defined as the length of the chain
  height: usize,
  actual: MSignableTransaction,
}

#[derive(Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Client,
  view: OtherScalar,
}

impl Bitcoin {
  pub async fn new(url: String) -> Bitcoin {
    Bitcoin {
      rpc: Client::new(&url, Auth::UserPass("serai".to_string(), "seraidex".to_string())).unwrap(),
      view: additional_key::<Bitcoin>(0).0,
    }
  }

  fn scanner(&self, spend: dfg::EdwardsPoint) -> Scanner {
    Scanner::from_view(ViewPair::new(spend.0, self.view), Network::Mainnet, None)
    //Ok(())
  }

  #[cfg(test)]
  fn empty_scanner() -> Scanner {
    use group::Group;
    Scanner::from_view(
      ViewPair::new(*dfg::EdwardsPoint::generator(), OtherScalar::one()),
      Network::Mainnet,
      Some(std::collections::HashSet::new()),
    )
  }

  #[cfg(test)]
  fn empty_address() -> Address {
    let address: bitcoin::util::address::Address =
      bitcoin::util::address::Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap();
    return address;
  }
}

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

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Ed25519;

  type Fee = Fee;
  type Transaction = Transaction;
  type Block = bitcoin::Block; //Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 10;

  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: dfg::EdwardsPoint) -> Self::Address {
    let address: Self::Address =
      Self::Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap();
    return address;
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // - defines height as chain length, so subtract 1 for block number
    let block_result = self.rpc.get_block_count().map_err(|_| CoinError::ConnectionError);
    let block_number = match block_result {
      Ok(val) => Ok(val as usize),
      Err(_) => return Err(CoinError::ConnectionError),
    };

    return block_number;
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let block_number = number as u64;
    let block_hash = self.rpc.get_block_hash(block_number - 1).unwrap();
    self.rpc.get_block(&block_hash).map_err(|_| CoinError::ConnectionError)
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: dfg::EdwardsPoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    return Err(CoinError::ConnectionError);
  }

  async fn is_confirmed(&self, tx: &[u8]) -> Result<bool, CoinError> {
    let txid_str = String::from_utf8(tx.to_vec()).unwrap();
    let txid = bitcoin::Txid::from_hex(&txid_str).unwrap(); //sha256d::Hash::from_hex(txid)?;
    let res1 = self.rpc.get_transaction(&txid, Option::Some(true)).unwrap();
    let tx_block_number = res1.info.blockheight.unwrap() as usize;

    Ok((self.get_latest_block_number().await.unwrap().saturating_sub(tx_block_number) + 1) >= 10)
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Ed25519>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut inputs: Vec<Output>,
    payments: &[(Address, u64)],
    fee: Fee,
  ) -> Result<SignableTransaction, CoinError> {
    let spend = keys.group_key();
    return Err(CoinError::ConnectionError);
  }

  async fn attempt_send(
    &self,
    transaction: SignableTransaction,
    included: &[u16],
  ) -> Result<Self::TransactionMachine, CoinError> {
    return Err(CoinError::ConnectionError);
  }

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    return Err(CoinError::ConnectionError);
    //self.rpc.publish_transaction(tx).await.map_err(|_| CoinError::ConnectionError)?;

    //Ok((tx.hash().to_vec(), tx.prefix.outputs.iter().map(|output| output.key.to_bytes()).collect()))
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    Self::Fee { per_weight: 36, mask: 66 }
  }

  #[cfg(test)]
  async fn mine_block(&self) {}

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {}
}

fn print_keys(key:&ProjectivePoint, tag: String) {
  println!("Tag : {}", tag);
  let key_encoded = key.to_encoded_point(false);
  dbg!(hex::encode(key_encoded.x().to_owned().unwrap()));
  dbg!(hex::encode(key_encoded.y().to_owned().unwrap()));
}

extern crate bitcoin_hashes;
use secp256k1::Message;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;

#[test]
fn test_signing() {
  use frost::{
    algorithm::Hram,
    curve::Secp256k1,
    algorithm::Schnorr,
    tests::{algorithm_machines, key_gen, sign},
  };
  use rand_core::OsRng;

  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);

  //print_keys(&keys[&1].group_key(), "1. Public Keys".to_string());

  for i in 1 ..= keys.len() as u16 {
    let (_, offset) = make_even(keys[&i].group_key());
    if offset == 0 {
      break;
    }
    let new_key = keys[&i].offset(Scalar::from(offset));
    dbg!(offset);

    //print_keys(&new_key.group_key(), "2. Public Keys".to_string());
    
    if let Some(x) = keys.get_mut(&i) {
      *x = new_key;
    }
  }

  //print_keys(&keys[&1].group_key(), "3. Public Keys".to_string());

  const MESSAGE: &'static [u8] = b"Hello, World!";

  let mut _sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, BitcoinHram>::new(), &keys), //&keys),
    MESSAGE,
  );
  let mut offset = 0;
  (_sig.R, offset) = make_even(_sig.R);
  _sig.s += Scalar::from(offset);

  //print_keys(&_sig.R, "3. R Keys".to_string());

  let sign_serialized = &_sig.serialize()[1..65];
  let sig = secp256k1::schnorr::Signature::from_slice(sign_serialized).unwrap();
  let msg = Message::from(sha256::Hash::hash(&MESSAGE));

  let R_compressed_key = _sig.R.to_encoded_point(true);
  let pubkey = secp256k1::XOnlyPublicKey::from_slice(&R_compressed_key.x().to_owned().unwrap()).unwrap();
  let _res = sig.verify(&msg, &pubkey).unwrap();
  dbg!(_res);
}
