#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

// Internal utilities for scanning transactions
mod scan;

// Primitive trait satisfactions
mod output;
mod transaction;
mod block;

// App-logic trait satisfactions
mod rpc;
mod scheduler;

pub(crate) fn hash_bytes(hash: bitcoin_serai::bitcoin::hashes::sha256d::Hash) -> [u8; 32] {
  use bitcoin_serai::bitcoin::hashes::Hash;

  let mut res = hash.to_byte_array();
  res.reverse();
  res
}

#[tokio::main]
async fn main() {}

/*
use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as HashTrait,
    key::{Parity, XOnlyPublicKey},
    consensus::{Encodable, Decodable},
    script::Instruction,
    Transaction, Block, ScriptBuf,
    opcodes::all::{OP_SHA256, OP_EQUALVERIFY},
  },
  wallet::{
    tweak_keys, p2tr_script_buf, ReceivedOutput, Scanner, TransactionError,
    SignableTransaction as BSignableTransaction, TransactionMachine,
  },
  rpc::{RpcError, Rpc},
};

#[cfg(test)]
use bitcoin_serai::bitcoin::{
  secp256k1::{SECP256K1, SecretKey, Message},
  PrivateKey, PublicKey,
  sighash::{EcdsaSighashType, SighashCache},
  script::PushBytesBuf,
  absolute::LockTime,
  Amount as BAmount, Sequence, Script, Witness, OutPoint,
  transaction::Version,
  blockdata::transaction::{TxIn, TxOut},
};

use serai_client::{
  primitives::{MAX_DATA_LEN, Coin, NetworkId, Amount, Balance},
  networks::bitcoin::Address,
};
*/

/*
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee(u64);

#[async_trait]
impl TransactionTrait<Bitcoin> for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    let mut hash = *self.compute_txid().as_raw_hash().as_byte_array();
    hash.reverse();
    hash
  }

  #[cfg(test)]
  async fn fee(&self, network: &Bitcoin) -> u64 {
    let mut value = 0;
    for input in &self.input {
      let output = input.previous_output;
      let mut hash = *output.txid.as_raw_hash().as_byte_array();
      hash.reverse();
      value += network.rpc.get_transaction(&hash).await.unwrap().output
        [usize::try_from(output.vout).unwrap()]
      .value
      .to_sat();
    }
    for output in &self.output {
      value -= output.value.to_sat();
    }
    value
  }
}

#[async_trait]
impl BlockTrait<Bitcoin> for Block {
  async fn time(&self, rpc: &Bitcoin) -> u64 {
    // Use the network median time defined in BIP-0113 since the in-block time isn't guaranteed to
    // be monotonic
    let mut timestamps = vec![u64::from(self.header.time)];
    let mut parent = self.parent();
    // BIP-0113 uses a median of the prior 11 blocks
    while timestamps.len() < 11 {
      let mut parent_block;
      while {
        parent_block = rpc.rpc.get_block(&parent).await;
        parent_block.is_err()
      } {
        log::error!("couldn't get parent block when trying to get block time: {parent_block:?}");
        sleep(Duration::from_secs(5)).await;
      }
      let parent_block = parent_block.unwrap();
      timestamps.push(u64::from(parent_block.header.time));
      parent = parent_block.parent();

      if parent == [0; 32] {
        break;
      }
    }
    timestamps.sort();
    timestamps[timestamps.len() / 2]
  }
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
  pub async fn new(url: String) -> Bitcoin {
    let mut res = Rpc::new(url.clone()).await;
    while let Err(e) = res {
      log::error!("couldn't connect to Bitcoin node: {e:?}");
      sleep(Duration::from_secs(5)).await;
      res = Rpc::new(url.clone()).await;
    }
    Bitcoin { rpc: res.unwrap() }
  }

  #[cfg(test)]
  pub async fn fresh_chain(&self) {
    if self.rpc.get_latest_block_number().await.unwrap() > 0 {
      self
        .rpc
        .rpc_call(
          "invalidateblock",
          serde_json::json!([hex::encode(self.rpc.get_block_hash(1).await.unwrap())]),
        )
        .await
        .unwrap()
    }
  }

  // This function panics on a node which doesn't follow the Bitcoin protocol, which is deemed fine
  async fn median_fee(&self, block: &Block) -> Result<Fee, NetworkError> {
    let mut fees = vec![];
    if block.txdata.len() > 1 {
      for tx in &block.txdata[1 ..] {
        let mut in_value = 0;
        for input in &tx.input {
          let mut input_tx = input.previous_output.txid.to_raw_hash().to_byte_array();
          input_tx.reverse();
          in_value += self
            .rpc
            .get_transaction(&input_tx)
            .await
            .map_err(|_| NetworkError::ConnectionError)?
            .output[usize::try_from(input.previous_output.vout).unwrap()]
          .value
          .to_sat();
        }
        let out = tx.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
        fees.push((in_value - out) / u64::try_from(tx.vsize()).unwrap());
      }
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // The DUST constant documentation notes a relay rule practically enforcing a
    // 1000 sat/kilo-vbyte minimum fee.
    Ok(Fee(fee.max(1)))
  }

  async fn make_signable_transaction(
    &self,
    block_number: usize,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    calculating_fee: bool,
  ) -> Result<Option<BSignableTransaction>, NetworkError> {
    for payment in payments {
      assert_eq!(payment.balance.coin, Coin::Bitcoin);
    }

    // TODO2: Use an fee representative of several blocks, cached inside Self
    let block_for_fee = self.get_block(block_number).await?;
    let fee = self.median_fee(&block_for_fee).await?;

    let payments = payments
      .iter()
      .map(|payment| {
        (
          payment.address.clone().into(),
          // If we're solely estimating the fee, don't specify the actual amount
          // This won't affect the fee calculation yet will ensure we don't hit a not enough funds
          // error
          if calculating_fee { Self::DUST } else { payment.balance.amount.0 },
        )
      })
      .collect::<Vec<_>>();

    match BSignableTransaction::new(
      inputs.iter().map(|input| input.output.clone()).collect(),
      &payments,
      change.clone().map(Into::into),
      None,
      fee.0,
    ) {
      Ok(signable) => Ok(Some(signable)),
      Err(TransactionError::NoInputs) => {
        panic!("trying to create a bitcoin transaction without inputs")
      }
      // No outputs left and the change isn't worth enough/not even enough funds to pay the fee
      Err(TransactionError::NoOutputs | TransactionError::NotEnoughFunds) => Ok(None),
      // amortize_fee removes payments which fall below the dust threshold
      Err(TransactionError::DustPayment) => panic!("dust payment despite removing dust"),
      Err(TransactionError::TooMuchData) => {
        panic!("too much data despite not specifying data")
      }
      Err(TransactionError::TooLowFee) => {
        panic!("created a transaction whose fee is below the minimum")
      }
      Err(TransactionError::TooLargeTransaction) => {
        panic!("created a too large transaction despite limiting inputs/outputs")
      }
    }
  }

  #[cfg(test)]
  pub fn sign_btc_input_for_p2pkh(
    tx: &Transaction,
    input_index: usize,
    private_key: &PrivateKey,
  ) -> ScriptBuf {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    let public_key = PublicKey::from_private_key(SECP256K1, private_key);
    let main_addr = BAddress::p2pkh(public_key, BNetwork::Regtest);

    let mut der = SECP256K1
      .sign_ecdsa_low_r(
        &Message::from_digest_slice(
          SighashCache::new(tx)
            .legacy_signature_hash(
              input_index,
              &main_addr.script_pubkey(),
              EcdsaSighashType::All.to_u32(),
            )
            .unwrap()
            .to_raw_hash()
            .as_ref(),
        )
        .unwrap(),
        &private_key.inner,
      )
      .serialize_der()
      .to_vec();
    der.push(1);

    ScriptBuf::builder()
      .push_slice(PushBytesBuf::try_from(der).unwrap())
      .push_key(&public_key)
      .into_script()
  }
}

fn address_from_key(key: ProjectivePoint) -> Address {
  Address::new(
    p2tr_script_buf(key).expect("creating address from key which isn't properly tweaked"),
  )
  .expect("couldn't create Serai-representable address for P2TR script")
}

#[async_trait]
impl Network for Bitcoin {
  type Scheduler = Scheduler<Bitcoin>;

  // 2 inputs should be 2 * 230 = 460 weight units
  // The output should be ~36 bytes, or 144 weight units
  // The overhead should be ~20 bytes at most, or 80 weight units
  // 684 weight units, 171 vbytes, round up to 200
  // 200 vbytes at 1 sat/weight (our current minimum fee, 4 sat/vbyte) = 800 sat fee for the
  // aggregation TX
  const COST_TO_AGGREGATE: u64 = 800;

  const MAX_OUTPUTS: usize = MAX_OUTPUTS;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::Curve>) {
    *keys = tweak_keys(keys);
    // Also create a scanner to assert these keys, and all expected paths, are usable
    scanner(keys.group_key());
  }

  #[cfg(test)]
  async fn external_address(&self, key: ProjectivePoint) -> Address {
    address_from_key(key)
  }

  fn branch_address(key: ProjectivePoint) -> Option<Address> {
    let (_, offsets, _) = scanner(key);
    Some(address_from_key(key + (ProjectivePoint::GENERATOR * offsets[&OutputType::Branch])))
  }

  fn change_address(key: ProjectivePoint) -> Option<Address> {
    let (_, offsets, _) = scanner(key);
    Some(address_from_key(key + (ProjectivePoint::GENERATOR * offsets[&OutputType::Change])))
  }

  fn forward_address(key: ProjectivePoint) -> Option<Address> {
    let (_, offsets, _) = scanner(key);
    Some(address_from_key(key + (ProjectivePoint::GENERATOR * offsets[&OutputType::Forwarded])))
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block_number(id).await.unwrap()
  }

  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    _: &EmptyClaim,
  ) -> bool {
    self.rpc.get_transaction(&eventuality.0).await.is_ok()
  }

  #[cfg(test)]
  async fn get_transaction_by_eventuality(&self, _: usize, id: &Eventuality) -> Transaction {
    self.rpc.get_transaction(&id.0).await.unwrap()
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    self
      .rpc
      .rpc_call::<Vec<String>>(
        "generatetoaddress",
        serde_json::json!([1, BAddress::p2sh(Script::new(), BNetwork::Regtest).unwrap()]),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    let secret_key = SecretKey::new(&mut rand_core::OsRng);
    let private_key = PrivateKey::new(secret_key, BNetwork::Regtest);
    let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
    let main_addr = BAddress::p2pkh(public_key, BNetwork::Regtest);

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([100, main_addr]))
      .await
      .unwrap();

    let tx = self.get_block(new_block).await.unwrap().txdata.swap_remove(0);
    let mut tx = Transaction {
      version: Version(2),
      lock_time: LockTime::ZERO,
      input: vec![TxIn {
        previous_output: OutPoint { txid: tx.compute_txid(), vout: 0 },
        script_sig: Script::new().into(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
      }],
      output: vec![TxOut {
        value: tx.output[0].value - BAmount::from_sat(10000),
        script_pubkey: address.clone().into(),
      }],
    };
    tx.input[0].script_sig = Self::sign_btc_input_for_p2pkh(&tx, 0, &private_key);

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.send_raw_transaction(&tx).await.unwrap();
    for _ in 0 .. Self::CONFIRMATIONS {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}

impl UtxoNetwork for Bitcoin {
  const MAX_INPUTS: usize = MAX_INPUTS;
}
*/
