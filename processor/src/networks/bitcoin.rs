use std::{time::Duration, io, collections::HashMap};

use async_trait::async_trait;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::ff::PrimeField;
use k256::{ProjectivePoint, Scalar};
use frost::{
  curve::{Curve, Secp256k1},
  ThresholdKeys,
};

use tokio::time::sleep;

use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as HashTrait,
    key::{Parity, XOnlyPublicKey},
    consensus::{Encodable, Decodable},
    script::Instruction,
    address::{NetworkChecked, Address as BAddress},
    OutPoint, TxOut, Transaction, Block, Network as BitcoinNetwork,
  },
  wallet::{
    tweak_keys, address_payload, ReceivedOutput, Scanner, TransactionError,
    SignableTransaction as BSignableTransaction, TransactionMachine,
  },
  rpc::{RpcError, Rpc},
};

#[cfg(test)]
use bitcoin_serai::bitcoin::{
  secp256k1::{SECP256K1, SecretKey, Message},
  PrivateKey, PublicKey,
  sighash::{EcdsaSighashType, SighashCache},
  script::{PushBytesBuf, Builder},
  absolute::LockTime,
  Sequence, Script, Witness, TxIn,
};

use serai_client::{
  primitives::{MAX_DATA_LEN, Coin as SeraiCoin, NetworkId, Amount, Balance},
  networks::bitcoin::Address,
};

use crate::{
  networks::{
    NetworkError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, SignableTransaction as SignableTransactionTrait,
    Eventuality as EventualityTrait, EventualitiesTracker, Network,
  },
  Payment,
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
  output: ReceivedOutput,
  data: Vec<u8>,
}

impl OutputTrait<Bitcoin> for Output {
  type Id = OutputId;

  fn kind(&self) -> OutputType {
    self.kind
  }

  fn id(&self) -> Self::Id {
    let mut res = OutputId::default();
    self.output.outpoint().consensus_encode(&mut res.as_mut()).unwrap();
    debug_assert_eq!(
      {
        let mut outpoint = vec![];
        self.output.outpoint().consensus_encode(&mut outpoint).unwrap();
        outpoint
      },
      res.as_ref().to_vec()
    );
    res
  }

  fn tx_id(&self) -> [u8; 32] {
    let mut hash = *self.output.outpoint().txid.as_raw_hash().as_byte_array();
    hash.reverse();
    hash
  }

  fn key(&self) -> ProjectivePoint {
    let script = &self.output.output().script_pubkey;
    assert!(script.is_v1_p2tr());
    let Instruction::PushBytes(key) = script.instructions_minimal().last().unwrap().unwrap() else {
      panic!("last item in v1 Taproot script wasn't bytes")
    };
    let key = XOnlyPublicKey::from_slice(key.as_ref())
      .expect("last item in v1 Taproot script wasn't x-only public key");
    Secp256k1::read_G(&mut key.public_key(Parity::Even).serialize().as_slice()).unwrap() -
      (ProjectivePoint::GENERATOR * self.output.offset())
  }

  fn balance(&self) -> Balance {
    Balance { coin: SeraiCoin::Bitcoin, amount: Amount(self.output.value()) }
  }

  fn data(&self) -> &[u8] {
    &self.data
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
      output: ReceivedOutput::read(reader)?,
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

#[async_trait]
impl TransactionTrait<Bitcoin> for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    let mut hash = *self.txid().as_raw_hash().as_byte_array();
    hash.reverse();
    hash
  }
  fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.consensus_encode(&mut buf).unwrap();
    buf
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
      .value;
    }
    for output in &self.output {
      value -= output.value;
    }
    value
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Eventuality {
  // We need to bind to the plan. While we could bind to the plan ID via an OP_RETURN, plans will
  // use distinct inputs and this is accordingly valid as a binding to a specific plan.
  plan_binding_input: OutPoint,
  outputs: Vec<TxOut>,
}

impl EventualityTrait for Eventuality {
  fn lookup(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 4);
    self.plan_binding_input.consensus_encode(&mut buf).unwrap();
    buf
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let plan_binding_input = OutPoint::consensus_decode(reader).map_err(|_| {
      io::Error::new(io::ErrorKind::Other, "couldn't decode outpoint in eventuality")
    })?;
    let outputs = Vec::<TxOut>::consensus_decode(reader).map_err(|_| {
      io::Error::new(io::ErrorKind::Other, "couldn't decode outputs in eventuality")
    })?;
    Ok(Eventuality { plan_binding_input, outputs })
  }
  fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 4 + 4 + (self.outputs.len() * (8 + 32)));
    self.plan_binding_input.consensus_encode(&mut buf).unwrap();
    self.outputs.consensus_encode(&mut buf).unwrap();
    buf
  }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
  transcript: RecommendedTranscript,
  actual: BSignableTransaction,
}
impl PartialEq for SignableTransaction {
  fn eq(&self, other: &SignableTransaction) -> bool {
    self.actual == other.actual
  }
}
impl Eq for SignableTransaction {}
impl SignableTransactionTrait for SignableTransaction {
  fn fee(&self) -> u64 {
    self.actual.fee()
  }
}

impl BlockTrait<Bitcoin> for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    let mut hash = *self.block_hash().as_raw_hash().as_byte_array();
    hash.reverse();
    hash
  }

  fn parent(&self) -> Self::Id {
    let mut hash = *self.header.prev_blockhash.as_raw_hash().as_byte_array();
    hash.reverse();
    hash
  }

  // TODO: Don't use this block's time, use the network time at this block
  // TODO: Confirm network time is monotonic, enabling its usage here
  fn time(&self) -> u64 {
    self.header.time.into()
  }

  fn median_fee(&self) -> Fee {
    // TODO
    Fee(20)
  }
}

const KEY_DST: &[u8] = b"Serai Bitcoin Output Offset";
lazy_static::lazy_static! {
  static ref BRANCH_OFFSET: Scalar = Secp256k1::hash_to_F(KEY_DST, b"branch");
  static ref CHANGE_OFFSET: Scalar = Secp256k1::hash_to_F(KEY_DST, b"change");
}

// Always construct the full scanner in order to ensure there's no collisions
fn scanner(
  key: ProjectivePoint,
) -> (Scanner, HashMap<OutputType, Scalar>, HashMap<Vec<u8>, OutputType>) {
  let mut scanner = Scanner::new(key).unwrap();
  let mut offsets = HashMap::from([(OutputType::External, Scalar::ZERO)]);

  let zero = Scalar::ZERO.to_repr();
  let zero_ref: &[u8] = zero.as_ref();
  let mut kinds = HashMap::from([(zero_ref.to_vec(), OutputType::External)]);

  let mut register = |kind, offset| {
    let offset = scanner.register_offset(offset).expect("offset collision");
    offsets.insert(kind, offset);

    let offset = offset.to_repr();
    let offset_ref: &[u8] = offset.as_ref();
    kinds.insert(offset_ref.to_vec(), kind);
  };

  register(OutputType::Branch, *BRANCH_OFFSET);
  register(OutputType::Change, *CHANGE_OFFSET);

  (scanner, offsets, kinds)
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
  pub async fn new(url: String) -> Bitcoin {
    Bitcoin { rpc: Rpc::new(url).await.expect("couldn't create a Bitcoin RPC") }
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

  async fn make_signable_transaction(
    &self,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    fee: Fee,
    calculating_fee: bool,
  ) -> Option<BSignableTransaction> {
    let payments = payments
      .iter()
      .map(|payment| {
        (
          payment.address.0.clone(),
          // If we're solely estimating the fee, don't specify the actual amount
          // This won't affect the fee calculation yet will ensure we don't hit a not enough funds
          // error
          if calculating_fee { Self::DUST } else { payment.amount },
        )
      })
      .collect::<Vec<_>>();

    match BSignableTransaction::new(
      inputs.iter().map(|input| input.output.clone()).collect(),
      &payments,
      change.as_ref().map(|change| change.0.clone()),
      None,
      fee.0,
    ) {
      Ok(signable) => Some(signable),
      Err(TransactionError::NoInputs) => {
        panic!("trying to create a bitcoin transaction without inputs")
      }
      // No outputs left and the change isn't worth enough
      Err(TransactionError::NoOutputs) => None,
      // amortize_fee removes payments which fall below the dust threshold
      Err(TransactionError::DustPayment) => panic!("dust payment despite removing dust"),
      Err(TransactionError::TooMuchData) => panic!("too much data despite not specifying data"),
      Err(TransactionError::TooLowFee) => {
        panic!("created a transaction whose fee is below the minimum")
      }
      Err(TransactionError::NotEnoughFunds) => {
        // Mot even enough funds to pay the fee
        None
      }
      Err(TransactionError::TooLargeTransaction) => {
        panic!("created a too large transaction despite limiting inputs/outputs")
      }
    }
  }
}

#[async_trait]
impl Network for Bitcoin {
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction = Transaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type Eventuality = Eventuality;
  type TransactionMachine = TransactionMachine;

  type Address = Address;

  const NETWORK: NetworkId = NetworkId::Bitcoin;
  const ID: &'static str = "Bitcoin";
  const ESTIMATED_BLOCK_TIME_IN_SECONDS: usize = 600;
  const CONFIRMATIONS: usize = 6;

  // 0.0001 BTC, 10,000 satoshis
  #[allow(clippy::inconsistent_digit_grouping)]
  const DUST: u64 = 1_00_000_000 / 10_000;

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

  fn tweak_keys(keys: &mut ThresholdKeys<Self::Curve>) {
    *keys = tweak_keys(keys);
    // Also create a scanner to assert these keys, and all expected paths, are usable
    scanner(keys.group_key());
  }

  fn address(key: ProjectivePoint) -> Address {
    Address(BAddress::<NetworkChecked>::new(BitcoinNetwork::Bitcoin, address_payload(key).unwrap()))
  }

  fn branch_address(key: ProjectivePoint) -> Address {
    let (_, offsets, _) = scanner(key);
    Self::address(key + (ProjectivePoint::GENERATOR * offsets[&OutputType::Branch]))
  }

  fn change_address(key: ProjectivePoint) -> Address {
    let (_, offsets, _) = scanner(key);
    Self::address(key + (ProjectivePoint::GENERATOR * offsets[&OutputType::Change]))
  }

  async fn get_latest_block_number(&self) -> Result<usize, NetworkError> {
    self.rpc.get_latest_block_number().await.map_err(|_| NetworkError::ConnectionError)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, NetworkError> {
    let block_hash =
      self.rpc.get_block_hash(number).await.map_err(|_| NetworkError::ConnectionError)?;
    self.rpc.get_block(&block_hash).await.map_err(|_| NetworkError::ConnectionError)
  }

  async fn get_outputs(&self, block: &Self::Block, key: ProjectivePoint) -> Vec<Output> {
    let (scanner, _, kinds) = scanner(key);

    let mut outputs = vec![];
    // Skip the coinbase transaction which is burdened by maturity
    for tx in &block.txdata[1 ..] {
      for output in scanner.scan_transaction(tx) {
        let offset_repr = output.offset().to_repr();
        let offset_repr_ref: &[u8] = offset_repr.as_ref();
        let kind = kinds[offset_repr_ref];

        let mut data = if kind == OutputType::External {
          (|| {
            for output in &tx.output {
              if output.script_pubkey.is_op_return() {
                match output.script_pubkey.instructions_minimal().last() {
                  Some(Ok(Instruction::PushBytes(data))) => return data.as_bytes().to_vec(),
                  _ => continue,
                }
              }
            }
            vec![]
          })()
        } else {
          vec![]
        };
        data.truncate(MAX_DATA_LEN.try_into().unwrap());

        let output = Output { kind, output, data };
        assert_eq!(output.tx_id(), tx.id());
        outputs.push(output);
      }
    }

    outputs
  }

  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Eventuality>,
    block: &Self::Block,
  ) -> HashMap<[u8; 32], (usize, Transaction)> {
    let mut res = HashMap::new();
    if eventualities.map.is_empty() {
      return res;
    }

    async fn check_block(
      eventualities: &mut EventualitiesTracker<Eventuality>,
      block: &Block,
      res: &mut HashMap<[u8; 32], (usize, Transaction)>,
    ) {
      for tx in &block.txdata[1 ..] {
        let input = &tx.input[0].previous_output;
        let mut lookup = Vec::with_capacity(4 + 32);
        input.consensus_encode(&mut lookup).unwrap();
        if let Some((plan, eventuality)) = eventualities.map.remove(&lookup) {
          // Sanity, as this is guaranteed by how the lookup is performed
          assert_eq!(input, &eventuality.plan_binding_input);
          // If the multisig is honest, then the Eventuality's outputs should match the outputs of
          // this transaction
          // This panic is fine as this multisig being dishonest will require intervention on
          // Substrate to trigger a slash, and then an update to the processor to handle the exact
          // adjustments needed
          // Panicking here is effectively triggering the halt we need to perform anyways
          assert_eq!(
            tx.output, eventuality.outputs,
            "dishonest multisig spent input on distinct set of outputs"
          );

          res.insert(plan, (eventualities.block_number, tx.clone()));
        }
      }

      eventualities.block_number += 1;
    }

    let this_block_hash = block.id();
    let this_block_num = (async {
      loop {
        match self.rpc.get_block_number(&this_block_hash).await {
          Ok(number) => return number,
          Err(e) => {
            log::error!("couldn't get the block number for {}: {}", hex::encode(this_block_hash), e)
          }
        }
        sleep(Duration::from_secs(60)).await;
      }
    })
    .await;

    for block_num in (eventualities.block_number + 1) .. this_block_num {
      let block = {
        let mut block;
        while {
          block = self.get_block(block_num).await;
          block.is_err()
        } {
          log::error!("couldn't get block {}: {}", block_num, block.err().unwrap());
          sleep(Duration::from_secs(60)).await;
        }
        block.unwrap()
      };

      check_block(eventualities, &block, &mut res).await;
    }

    // Also check the current block
    check_block(eventualities, block, &mut res).await;
    assert_eq!(eventualities.block_number, this_block_num);

    res
  }

  async fn needed_fee(
    &self,
    _: usize,
    _: &[u8; 32],
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    fee_rate: Fee,
  ) -> Result<Option<u64>, NetworkError> {
    Ok(
      self
        .make_signable_transaction(inputs, payments, change, fee_rate, true)
        .await
        .map(|signable| signable.needed_fee()),
    )
  }

  async fn signable_transaction(
    &self,
    _: usize,
    plan_id: &[u8; 32],
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    fee_rate: Fee,
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError> {
    Ok(self.make_signable_transaction(inputs, payments, change, fee_rate, false).await.map(
      |signable| {
        let mut transcript =
          RecommendedTranscript::new(b"Serai Processor Bitcoin Transaction Transcript");
        transcript.append_message(b"plan", plan_id);

        let plan_binding_input = *inputs[0].output.outpoint();
        let outputs = signable.outputs().to_vec();

        (
          SignableTransaction { transcript, actual: signable },
          Eventuality { plan_binding_input, outputs },
        )
      },
    ))
  }

  async fn attempt_send(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    Ok(
      transaction
        .actual
        .clone()
        .multisig(keys.clone(), transaction.transcript)
        .expect("used the wrong keys"),
    )
  }

  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<(), NetworkError> {
    match self.rpc.send_raw_transaction(tx).await {
      Ok(_) => (),
      Err(RpcError::ConnectionError) => Err(NetworkError::ConnectionError)?,
      // TODO: Distinguish already in pool vs double spend (other signing attempt succeeded) vs
      // invalid transaction
      Err(e) => panic!("failed to publish TX {}: {e}", tx.txid()),
    }
    Ok(())
  }

  async fn get_transaction(&self, id: &[u8; 32]) -> Result<Transaction, NetworkError> {
    self.rpc.get_transaction(id).await.map_err(|_| NetworkError::ConnectionError)
  }

  fn confirm_completion(&self, eventuality: &Self::Eventuality, tx: &Transaction) -> bool {
    (eventuality.plan_binding_input == tx.input[0].previous_output) &&
      (eventuality.outputs == tx.output)
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block_number(id).await.unwrap()
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Fee {
    Fee(1)
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    self
      .rpc
      .rpc_call::<Vec<String>>(
        "generatetoaddress",
        serde_json::json!([1, BAddress::p2sh(Script::empty(), BitcoinNetwork::Regtest).unwrap()]),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    let secret_key = SecretKey::new(&mut rand_core::OsRng);
    let private_key = PrivateKey::new(secret_key, BitcoinNetwork::Regtest);
    let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
    let main_addr = BAddress::p2pkh(&public_key, BitcoinNetwork::Regtest);

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr]))
      .await
      .unwrap();

    for _ in 0 .. 100 {
      self.mine_block().await;
    }

    let tx = self.get_block(new_block).await.unwrap().txdata.swap_remove(0);
    let mut tx = Transaction {
      version: 2,
      lock_time: LockTime::ZERO,
      input: vec![TxIn {
        previous_output: OutPoint { txid: tx.txid(), vout: 0 },
        script_sig: Script::empty().into(),
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
          SighashCache::new(&tx)
            .legacy_signature_hash(0, &main_addr.script_pubkey(), EcdsaSighashType::All.to_u32())
            .unwrap()
            .to_raw_hash(),
        ),
        &private_key.inner,
      )
      .serialize_der()
      .to_vec();
    der.push(1);
    tx.input[0].script_sig = Builder::new()
      .push_slice(PushBytesBuf::try_from(der).unwrap())
      .push_key(&public_key)
      .into_script();

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.send_raw_transaction(&tx).await.unwrap();
    for _ in 0 .. Self::CONFIRMATIONS {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}
