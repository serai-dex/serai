use std::{sync::OnceLock, time::Duration, io, collections::HashMap};

use async_trait::async_trait;

use scale::{Encode, Decode};

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

use crate::{
  networks::{
    NetworkError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, SignableTransaction as SignableTransactionTrait,
    Eventuality as EventualityTrait, EventualitiesTracker, Network, UtxoNetwork,
  },
  Payment,
  multisigs::scheduler::utxo::Scheduler,
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
  presumed_origin: Option<Address>,
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
    assert!(script.is_p2tr());
    let Instruction::PushBytes(key) = script.instructions_minimal().last().unwrap().unwrap() else {
      panic!("last item in v1 Taproot script wasn't bytes")
    };
    let key = XOnlyPublicKey::from_slice(key.as_ref())
      .expect("last item in v1 Taproot script wasn't x-only public key");
    Secp256k1::read_G(&mut key.public_key(Parity::Even).serialize().as_slice()).unwrap() -
      (ProjectivePoint::GENERATOR * self.output.offset())
  }

  fn presumed_origin(&self) -> Option<Address> {
    self.presumed_origin.clone()
  }

  fn balance(&self) -> Balance {
    Balance { coin: Coin::Bitcoin, amount: Amount(self.output.value()) }
  }

  fn data(&self) -> &[u8] {
    &self.data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.kind.write(writer)?;
    let presumed_origin: Option<Vec<u8>> = self.presumed_origin.clone().map(Into::into);
    writer.write_all(&presumed_origin.encode())?;
    self.output.write(writer)?;
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)
  }

  fn read<R: io::Read>(mut reader: &mut R) -> io::Result<Self> {
    Ok(Output {
      kind: OutputType::read(reader)?,
      presumed_origin: {
        let mut io_reader = scale::IoReader(reader);
        let res = Option::<Vec<u8>>::decode(&mut io_reader)
          .unwrap()
          .map(|address| Address::try_from(address).unwrap());
        reader = io_reader.0;
        res
      },
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Eventuality([u8; 32]);

#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct EmptyClaim;
impl AsRef<[u8]> for EmptyClaim {
  fn as_ref(&self) -> &[u8] {
    &[]
  }
}
impl AsMut<[u8]> for EmptyClaim {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut []
  }
}

impl EventualityTrait for Eventuality {
  type Claim = EmptyClaim;
  type Completion = Transaction;

  fn lookup(&self) -> Vec<u8> {
    self.0.to_vec()
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut id = [0; 32];
    reader
      .read_exact(&mut id)
      .map_err(|_| io::Error::other("couldn't decode ID in eventuality"))?;
    Ok(Eventuality(id))
  }
  fn serialize(&self) -> Vec<u8> {
    self.0.to_vec()
  }

  fn claim(_: &Transaction) -> EmptyClaim {
    EmptyClaim
  }
  fn serialize_completion(completion: &Transaction) -> Vec<u8> {
    let mut buf = vec![];
    completion.consensus_encode(&mut buf).unwrap();
    buf
  }
  fn read_completion<R: io::Read>(reader: &mut R) -> io::Result<Transaction> {
    Transaction::consensus_decode(&mut io::BufReader::with_capacity(0, reader))
      .map_err(|e| io::Error::other(format!("{e}")))
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

#[async_trait]
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

const KEY_DST: &[u8] = b"Serai Bitcoin Output Offset";
static BRANCH_OFFSET: OnceLock<Scalar> = OnceLock::new();
static CHANGE_OFFSET: OnceLock<Scalar> = OnceLock::new();
static FORWARD_OFFSET: OnceLock<Scalar> = OnceLock::new();

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

  register(
    OutputType::Branch,
    *BRANCH_OFFSET.get_or_init(|| Secp256k1::hash_to_F(KEY_DST, b"branch")),
  );
  register(
    OutputType::Change,
    *CHANGE_OFFSET.get_or_init(|| Secp256k1::hash_to_F(KEY_DST, b"change")),
  );
  register(
    OutputType::Forwarded,
    *FORWARD_OFFSET.get_or_init(|| Secp256k1::hash_to_F(KEY_DST, b"forward")),
  );

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
        fees.push((in_value - out) / tx.weight().to_wu());
      }
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // The DUST constant documentation notes a relay rule practically enforcing a
    // 1000 sat/kilo-vbyte minimum fee.
    //
    // 1000 sat/kilo-vbyte is 1000 sat/4-kilo-weight (250 sat/kilo-weight).
    // Since bitcoin-serai takes fee per weight, we'd need to pass 0.25 to achieve this fee rate.
    // Accordingly, setting 1 is 4x the current relay rule minimum (and should be more than safe).
    // TODO: Rewrite to fee_per_vbyte, not fee_per_weight?
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

  // Expected script has to start with SHA256 PUSH MSG_HASH OP_EQUALVERIFY ..
  fn segwit_data_pattern(script: &ScriptBuf) -> Option<bool> {
    let mut ins = script.instructions();

    // first item should be SHA256 code
    if ins.next()?.ok()?.opcode()? != OP_SHA256 {
      return Some(false);
    }

    // next should be a data push
    ins.next()?.ok()?.push_bytes()?;

    // next should be a equality check
    if ins.next()?.ok()?.opcode()? != OP_EQUALVERIFY {
      return Some(false);
    }

    Some(true)
  }

  fn extract_serai_data(tx: &Transaction) -> Vec<u8> {
    // check outputs
    let mut data = (|| {
      for output in &tx.output {
        if output.script_pubkey.is_op_return() {
          match output.script_pubkey.instructions_minimal().last() {
            Some(Ok(Instruction::PushBytes(data))) => return data.as_bytes().to_vec(),
            _ => continue,
          }
        }
      }
      vec![]
    })();

    // check inputs
    if data.is_empty() {
      for input in &tx.input {
        let witness = input.witness.to_vec();
        // expected witness at least has to have 2 items, msg and the redeem script.
        if witness.len() >= 2 {
          let redeem_script = ScriptBuf::from_bytes(witness.last().unwrap().clone());
          if Self::segwit_data_pattern(&redeem_script) == Some(true) {
            data.clone_from(&witness[witness.len() - 2]); // len() - 1 is the redeem_script
            break;
          }
        }
      }
    }

    data.truncate(MAX_DATA_LEN.try_into().unwrap());
    data
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

// Bitcoin has a max weight of 400,000 (MAX_STANDARD_TX_WEIGHT)
// A non-SegWit TX will have 4 weight units per byte, leaving a max size of 100,000 bytes
// While our inputs are entirely SegWit, such fine tuning is not necessary and could create
// issues in the future (if the size decreases or we misevaluate it)
// It also offers a minimal amount of benefit when we are able to logarithmically accumulate
// inputs
// For 128-byte inputs (36-byte output specification, 64-byte signature, whatever overhead) and
// 64-byte outputs (40-byte script, 8-byte amount, whatever overhead), they together take up 192
// bytes
// 100,000 / 192 = 520
// 520 * 192 leaves 160 bytes of overhead for the transaction structure itself
const MAX_INPUTS: usize = 520;
const MAX_OUTPUTS: usize = 520;

fn address_from_key(key: ProjectivePoint) -> Address {
  Address::new(
    p2tr_script_buf(key).expect("creating address from key which isn't properly tweaked"),
  )
  .expect("couldn't create Serai-representable address for P2TR script")
}

#[async_trait]
impl Network for Bitcoin {
  type Curve = Secp256k1;

  type Transaction = Transaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type Eventuality = Eventuality;
  type TransactionMachine = TransactionMachine;

  type Scheduler = Scheduler<Bitcoin>;

  type Address = Address;

  const NETWORK: NetworkId = NetworkId::Bitcoin;
  const ID: &'static str = "Bitcoin";
  const ESTIMATED_BLOCK_TIME_IN_SECONDS: usize = 600;
  const CONFIRMATIONS: usize = 6;

  /*
    A Taproot input is:
    - 36 bytes for the OutPoint
    - 0 bytes for the script (+1 byte for the length)
    - 4 bytes for the sequence
    Per https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format

    There's also:
    - 1 byte for the witness length
    - 1 byte for the signature length
    - 64 bytes for the signature
    which have the SegWit discount.

    (4 * (36 + 1 + 4)) + (1 + 1 + 64) = 164 + 66 = 230 weight units
    230 ceil div 4 = 57 vbytes

    Bitcoin defines multiple minimum feerate constants *per kilo-vbyte*. Currently, these are:
    - 1000 sat/kilo-vbyte for a transaction to be relayed
    - Each output's value must exceed the fee of the TX spending it at 3000 sat/kilo-vbyte
    The DUST constant needs to be determined by the latter.
    Since these are solely relay rules, and may be raised, we require all outputs be spendable
    under a 5000 sat/kilo-vbyte fee rate.

    5000 sat/kilo-vbyte = 5 sat/vbyte
    5 * 57 = 285 sats/spent-output

    Even if an output took 100 bytes (it should be just ~29-43), taking 400 weight units, adding
    100 vbytes, tripling the transaction size, then the sats/tx would be < 1000.

    Increase by an order of magnitude, in order to ensure this is actually worth our time, and we
    get 10,000 satoshis.
  */
  const DUST: u64 = 10_000;

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

        let output = Output { kind, presumed_origin: None, output, data: vec![] };
        assert_eq!(output.tx_id(), tx.id());
        outputs.push(output);
      }

      if outputs.is_empty() {
        continue;
      }

      // populate the outputs with the origin and data
      let presumed_origin = {
        // This may identify the P2WSH output *embedding the InInstruction* as the origin, which
        // would be a bit trickier to spend that a traditional output...
        // There's no risk of the InInstruction going missing as it'd already be on-chain though
        // We *could* parse out the script *without the InInstruction prefix* and declare that the
        // origin
        // TODO
        let spent_output = {
          let input = &tx.input[0];
          let mut spent_tx = input.previous_output.txid.as_raw_hash().to_byte_array();
          spent_tx.reverse();
          let mut tx;
          while {
            tx = self.rpc.get_transaction(&spent_tx).await;
            tx.is_err()
          } {
            log::error!("couldn't get transaction from bitcoin node: {tx:?}");
            sleep(Duration::from_secs(5)).await;
          }
          tx.unwrap().output.swap_remove(usize::try_from(input.previous_output.vout).unwrap())
        };
        Address::new(spent_output.script_pubkey)
      };
      let data = Self::extract_serai_data(tx);
      for output in &mut outputs {
        if output.kind == OutputType::External {
          output.data.clone_from(&data);
        }
        output.presumed_origin.clone_from(&presumed_origin);
      }
    }

    outputs
  }

  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Eventuality>,
    block: &Self::Block,
  ) -> HashMap<[u8; 32], (usize, [u8; 32], Transaction)> {
    let mut res = HashMap::new();
    if eventualities.map.is_empty() {
      return res;
    }

    fn check_block(
      eventualities: &mut EventualitiesTracker<Eventuality>,
      block: &Block,
      res: &mut HashMap<[u8; 32], (usize, [u8; 32], Transaction)>,
    ) {
      for tx in &block.txdata[1 ..] {
        if let Some((plan, _)) = eventualities.map.remove(tx.id().as_slice()) {
          res.insert(plan, (eventualities.block_number, tx.id(), tx.clone()));
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

      check_block(eventualities, &block, &mut res);
    }

    // Also check the current block
    check_block(eventualities, block, &mut res);
    assert_eq!(eventualities.block_number, this_block_num);

    res
  }

  async fn needed_fee(
    &self,
    block_number: usize,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
  ) -> Result<Option<u64>, NetworkError> {
    Ok(
      self
        .make_signable_transaction(block_number, inputs, payments, change, true)
        .await?
        .map(|signable| signable.needed_fee()),
    )
  }

  async fn signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    _key: ProjectivePoint,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    (): &(),
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError> {
    Ok(self.make_signable_transaction(block_number, inputs, payments, change, false).await?.map(
      |signable| {
        let mut transcript =
          RecommendedTranscript::new(b"Serai Processor Bitcoin Transaction Transcript");
        transcript.append_message(b"plan", plan_id);

        let eventuality = Eventuality(signable.txid());
        (SignableTransaction { transcript, actual: signable }, eventuality)
      },
    ))
  }

  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    Ok(
      transaction
        .actual
        .clone()
        .multisig(&keys, transaction.transcript)
        .expect("used the wrong keys"),
    )
  }

  async fn publish_completion(&self, tx: &Transaction) -> Result<(), NetworkError> {
    match self.rpc.send_raw_transaction(tx).await {
      Ok(_) => (),
      Err(RpcError::ConnectionError) => Err(NetworkError::ConnectionError)?,
      // TODO: Distinguish already in pool vs double spend (other signing attempt succeeded) vs
      // invalid transaction
      Err(e) => panic!("failed to publish TX {}: {e}", tx.compute_txid()),
    }
    Ok(())
  }

  async fn confirm_completion(
    &self,
    eventuality: &Self::Eventuality,
    _: &EmptyClaim,
  ) -> Result<Option<Transaction>, NetworkError> {
    Ok(Some(
      self.rpc.get_transaction(&eventuality.0).await.map_err(|_| NetworkError::ConnectionError)?,
    ))
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
