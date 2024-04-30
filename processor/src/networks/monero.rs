use std::{time::Duration, collections::HashMap, io};

use async_trait::async_trait;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};
use frost::{curve::Ed25519, ThresholdKeys};

use monero_serai::{
  Protocol,
  ringct::RctType,
  transaction::Transaction,
  block::Block,
  rpc::{RpcError, HttpRpc, Rpc},
  wallet::{
    ViewPair, Scanner,
    address::{Network as MoneroNetwork, SubaddressIndex, AddressSpec},
    Fee, SpendableOutput, Change, Decoys, TransactionError,
    SignableTransaction as MSignableTransaction, Eventuality, TransactionMachine,
  },
};

use tokio::time::sleep;

pub use serai_client::{
  primitives::{MAX_DATA_LEN, Coin, NetworkId, Amount, Balance},
  networks::monero::Address,
};

use crate::{
  Payment, additional_key,
  networks::{
    NetworkError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, SignableTransaction as SignableTransactionTrait,
    Eventuality as EventualityTrait, EventualitiesTracker, Network, UtxoNetwork,
  },
  multisigs::scheduler::utxo::Scheduler,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output(SpendableOutput, Vec<u8>);

const EXTERNAL_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(0, 0);
const BRANCH_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(1, 0);
const CHANGE_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(2, 0);
const FORWARD_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(3, 0);

impl OutputTrait<Monero> for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While we already are immune, thanks to using featured address, this doesn't hurt and is
  // technically more efficient.
  type Id = [u8; 32];

  fn kind(&self) -> OutputType {
    match self.0.output.metadata.subaddress {
      EXTERNAL_SUBADDRESS => OutputType::External,
      BRANCH_SUBADDRESS => OutputType::Branch,
      CHANGE_SUBADDRESS => OutputType::Change,
      FORWARD_SUBADDRESS => OutputType::Forwarded,
      _ => panic!("unrecognized address was scanned for"),
    }
  }

  fn id(&self) -> Self::Id {
    self.0.output.data.key.compress().to_bytes()
  }

  fn tx_id(&self) -> [u8; 32] {
    self.0.output.absolute.tx
  }

  fn key(&self) -> EdwardsPoint {
    EdwardsPoint(self.0.output.data.key - (EdwardsPoint::generator().0 * self.0.key_offset()))
  }

  fn presumed_origin(&self) -> Option<Address> {
    None
  }

  fn balance(&self) -> Balance {
    Balance { coin: Coin::Monero, amount: Amount(self.0.commitment().amount) }
  }

  fn data(&self) -> &[u8] {
    &self.1
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.0.write(writer)?;
    writer.write_all(&u16::try_from(self.1.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.1)?;
    Ok(())
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let output = SpendableOutput::read(reader)?;

    let mut data_len = [0; 2];
    reader.read_exact(&mut data_len)?;

    let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
    reader.read_exact(&mut data)?;

    Ok(Output(output, data))
  }
}

#[async_trait]
impl TransactionTrait<Monero> for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash()
  }

  #[cfg(test)]
  async fn fee(&self, _: &Monero) -> u64 {
    self.rct_signatures.base.fee
  }
}

impl EventualityTrait for Eventuality {
  type Claim = [u8; 32];
  type Completion = Transaction;

  // Use the TX extra to look up potential matches
  // While anyone can forge this, a transaction with distinct outputs won't actually match
  // Extra includess the one time keys which are derived from the plan ID, so a collision here is a
  // hash collision
  fn lookup(&self) -> Vec<u8> {
    self.extra().to_vec()
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Eventuality::read(reader)
  }
  fn serialize(&self) -> Vec<u8> {
    self.serialize()
  }

  fn claim(tx: &Transaction) -> [u8; 32] {
    tx.id()
  }
  fn serialize_completion(completion: &Transaction) -> Vec<u8> {
    completion.serialize()
  }
  fn read_completion<R: io::Read>(reader: &mut R) -> io::Result<Transaction> {
    Transaction::read(reader)
  }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
  transcript: RecommendedTranscript,
  actual: MSignableTransaction,
}
impl SignableTransactionTrait for SignableTransaction {
  fn fee(&self) -> u64 {
    self.actual.fee()
  }
}

#[async_trait]
impl BlockTrait<Monero> for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash()
  }

  fn parent(&self) -> Self::Id {
    self.header.previous
  }

  async fn time(&self, rpc: &Monero) -> u64 {
    // Constant from Monero
    const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW: u64 = 60;

    // If Monero doesn't have enough blocks to build a window, it doesn't define a network time
    if (self.number().unwrap() + 1) < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
      // Use the block number as the time
      return self.number().unwrap();
    }

    let mut timestamps = vec![self.header.timestamp];
    let mut parent = self.parent();
    while u64::try_from(timestamps.len()).unwrap() < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
      let mut parent_block;
      while {
        parent_block = rpc.rpc.get_block(parent).await;
        parent_block.is_err()
      } {
        log::error!("couldn't get parent block when trying to get block time: {parent_block:?}");
        sleep(Duration::from_secs(5)).await;
      }
      let parent_block = parent_block.unwrap();
      timestamps.push(parent_block.header.timestamp);
      parent = parent_block.parent();

      if parent_block.number().unwrap() == 0 {
        break;
      }
    }
    timestamps.sort();

    // Because 60 has two medians, Monero's epee picks the in-between value, calculated by the
    // following formula (from the "get_mid" function)
    let n = timestamps.len() / 2;
    let a = timestamps[n - 1];
    let b = timestamps[n];
    #[rustfmt::skip] // Enables Ctrl+F'ing for everything after the `= `
    let res = (a/2) + (b/2) + ((a - 2*(a/2)) + (b - 2*(b/2)))/2;
    // Technically, res may be 1 if all prior blocks had a timestamp by 0, which would break
    // monotonicity with our above definition of height as time
    // Monero also solely requires the block's time not be less than the median, it doesn't ensure
    // it advances the median forward
    // Ensure monotonicity despite both these issues by adding the block number to the median time
    res + self.number().unwrap()
  }
}

#[derive(Clone, Debug)]
pub struct Monero {
  rpc: Rpc<HttpRpc>,
}
// Shim required for testing/debugging purposes due to generic arguments also necessitating trait
// bounds
impl PartialEq for Monero {
  fn eq(&self, _: &Self) -> bool {
    true
  }
}
impl Eq for Monero {}

#[allow(clippy::needless_pass_by_value)] // Needed to satisfy API expectations
fn map_rpc_err(err: RpcError) -> NetworkError {
  if let RpcError::InvalidNode(reason) = &err {
    log::error!("Monero RpcError::InvalidNode({reason})");
  } else {
    log::debug!("Monero RpcError {err:?}");
  }
  NetworkError::ConnectionError
}

impl Monero {
  pub async fn new(url: String) -> Monero {
    let mut res = HttpRpc::new(url.clone()).await;
    while let Err(e) = res {
      log::error!("couldn't connect to Monero node: {e:?}");
      tokio::time::sleep(Duration::from_secs(5)).await;
      res = HttpRpc::new(url.clone()).await;
    }
    Monero { rpc: res.unwrap() }
  }

  fn view_pair(spend: EdwardsPoint) -> ViewPair {
    ViewPair::new(spend.0, Zeroizing::new(additional_key::<Monero>(0).0))
  }

  fn address_internal(spend: EdwardsPoint, subaddress: Option<SubaddressIndex>) -> Address {
    Address::new(Self::view_pair(spend).address(
      MoneroNetwork::Mainnet,
      AddressSpec::Featured { subaddress, payment_id: None, guaranteed: true },
    ))
    .unwrap()
  }

  fn scanner(spend: EdwardsPoint) -> Scanner {
    let mut scanner = Scanner::from_view(Self::view_pair(spend), None);
    debug_assert!(EXTERNAL_SUBADDRESS.is_none());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner.register_subaddress(FORWARD_SUBADDRESS.unwrap());
    scanner
  }

  async fn median_fee(&self, block: &Block) -> Result<Fee, NetworkError> {
    let mut fees = vec![];
    for tx_hash in &block.txs {
      let tx =
        self.rpc.get_transaction(*tx_hash).await.map_err(|_| NetworkError::ConnectionError)?;
      // Only consider fees from RCT transactions, else the fee property read wouldn't be accurate
      if tx.rct_signatures.rct_type() != RctType::Null {
        continue;
      }
      // This isn't entirely accurate as Bulletproof TXs will have a higher weight than their
      // serialization length
      // It's likely 'good enough'
      // TODO2: Improve
      fees.push(tx.rct_signatures.base.fee / u64::try_from(tx.serialize().len()).unwrap());
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // TODO: Set a sane minimum fee
    Ok(Fee { per_weight: fee.max(1500000), mask: 10000 })
  }

  async fn make_signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    calculating_fee: bool,
  ) -> Result<Option<(RecommendedTranscript, MSignableTransaction)>, NetworkError> {
    for payment in payments {
      assert_eq!(payment.balance.coin, Coin::Monero);
    }

    // TODO2: Use an fee representative of several blocks, cached inside Self
    let block_for_fee = self.get_block(block_number).await?;
    let fee_rate = self.median_fee(&block_for_fee).await?;

    // Get the protocol for the specified block number
    // For now, this should just be v16, the latest deployed protocol, since there's no upcoming
    // hard fork to be mindful of
    let get_protocol = || Protocol::v16;

    #[cfg(not(test))]
    let protocol = get_protocol();
    // If this is a test, we won't be using a mainnet node and need a distinct protocol
    // determination
    // Just use whatever the node expects
    #[cfg(test)]
    let protocol = self.rpc.get_protocol().await.unwrap();

    // Hedge against the above codegen failing by having an always included runtime check
    if !cfg!(test) {
      assert_eq!(protocol, get_protocol());
    }

    // Check a fork hasn't occurred which this processor hasn't been updated for
    assert_eq!(protocol, self.rpc.get_protocol().await.map_err(map_rpc_err)?);

    let spendable_outputs = inputs.iter().map(|input| input.0.clone()).collect::<Vec<_>>();

    let mut transcript =
      RecommendedTranscript::new(b"Serai Processor Monero Transaction Transcript");
    transcript.append_message(b"plan", plan_id);

    // All signers need to select the same decoys
    // All signers use the same height and a seeded RNG to make sure they do so.
    let decoys = Decoys::fingerprintable_canonical_select(
      &mut ChaCha20Rng::from_seed(transcript.rng_seed(b"decoys")),
      &self.rpc,
      protocol.ring_len(),
      block_number + 1,
      &spendable_outputs,
    )
    .await
    .map_err(map_rpc_err)?;

    let inputs = spendable_outputs.into_iter().zip(decoys).collect::<Vec<_>>();

    // Monero requires at least two outputs
    // If we only have one output planned, add a dummy payment
    let mut payments = payments.to_vec();
    let outputs = payments.len() + usize::from(u8::from(change.is_some()));
    if outputs == 0 {
      return Ok(None);
    } else if outputs == 1 {
      payments.push(Payment {
        address: Address::new(
          ViewPair::new(EdwardsPoint::generator().0, Zeroizing::new(Scalar::ONE.0))
            .address(MoneroNetwork::Mainnet, AddressSpec::Standard),
        )
        .unwrap(),
        balance: Balance { coin: Coin::Monero, amount: Amount(0) },
        data: None,
      });
    }

    let payments = payments
      .into_iter()
      // If we're solely estimating the fee, don't actually specify an amount
      // This won't affect the fee calculation yet will ensure we don't hit an out of funds error
      .map(|payment| {
        (payment.address.into(), if calculating_fee { 0 } else { payment.balance.amount.0 })
      })
      .collect::<Vec<_>>();

    match MSignableTransaction::new(
      protocol,
      // Use the plan ID as the r_seed
      // This perfectly binds the plan while simultaneously allowing verifying the plan was
      // executed with no additional communication
      Some(Zeroizing::new(*plan_id)),
      inputs.clone(),
      payments,
      &Change::fingerprintable(change.as_ref().map(|change| change.clone().into())),
      vec![],
      fee_rate,
    ) {
      Ok(signable) => Ok(Some((transcript, signable))),
      Err(e) => match e {
        TransactionError::MultiplePaymentIds => {
          panic!("multiple payment IDs despite not supporting integrated addresses");
        }
        TransactionError::NoInputs |
        TransactionError::NoOutputs |
        TransactionError::InvalidDecoyQuantity |
        TransactionError::NoChange |
        TransactionError::TooManyOutputs |
        TransactionError::TooMuchData |
        TransactionError::TooLargeTransaction |
        TransactionError::WrongPrivateKey => {
          panic!("created an Monero invalid transaction: {e}");
        }
        TransactionError::ClsagError(_) |
        TransactionError::InvalidTransaction(_) |
        TransactionError::FrostError(_) => {
          panic!("supposedly unreachable (at this time) Monero error: {e}");
        }
        TransactionError::NotEnoughFunds { inputs, outputs, fee } => {
          log::debug!(
            "Monero NotEnoughFunds. inputs: {:?}, outputs: {:?}, fee: {fee}",
            inputs,
            outputs
          );
          Ok(None)
        }
        TransactionError::RpcError(e) => {
          log::error!("RpcError when preparing transaction: {e:?}");
          Err(map_rpc_err(e))
        }
      },
    }
  }

  #[cfg(test)]
  fn test_view_pair() -> ViewPair {
    ViewPair::new(*EdwardsPoint::generator(), Zeroizing::new(Scalar::ONE.0))
  }

  #[cfg(test)]
  fn test_scanner() -> Scanner {
    Scanner::from_view(Self::test_view_pair(), Some(std::collections::HashSet::new()))
  }

  #[cfg(test)]
  fn test_address() -> Address {
    Address::new(Self::test_view_pair().address(MoneroNetwork::Mainnet, AddressSpec::Standard))
      .unwrap()
  }
}

#[async_trait]
impl Network for Monero {
  type Curve = Ed25519;

  type Transaction = Transaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type Eventuality = Eventuality;
  type TransactionMachine = TransactionMachine;

  type Scheduler = Scheduler<Monero>;

  type Address = Address;

  const NETWORK: NetworkId = NetworkId::Monero;
  const ID: &'static str = "Monero";
  const ESTIMATED_BLOCK_TIME_IN_SECONDS: usize = 120;
  const CONFIRMATIONS: usize = 10;

  const MAX_OUTPUTS: usize = 16;

  // 0.01 XMR
  // TODO: Set a sane dust
  const DUST: u64 = 10000000000;

  // TODO
  const COST_TO_AGGREGATE: u64 = 0;

  // Monero doesn't require/benefit from tweaking
  fn tweak_keys(_: &mut ThresholdKeys<Self::Curve>) {}

  #[cfg(test)]
  async fn external_address(&self, key: EdwardsPoint) -> Address {
    Self::address_internal(key, EXTERNAL_SUBADDRESS)
  }

  fn branch_address(key: EdwardsPoint) -> Option<Address> {
    Some(Self::address_internal(key, BRANCH_SUBADDRESS))
  }

  fn change_address(key: EdwardsPoint) -> Option<Address> {
    Some(Self::address_internal(key, CHANGE_SUBADDRESS))
  }

  fn forward_address(key: EdwardsPoint) -> Option<Address> {
    Some(Self::address_internal(key, FORWARD_SUBADDRESS))
  }

  async fn get_latest_block_number(&self) -> Result<usize, NetworkError> {
    // Monero defines height as chain length, so subtract 1 for block number
    Ok(self.rpc.get_height().await.map_err(map_rpc_err)? - 1)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, NetworkError> {
    Ok(
      self
        .rpc
        .get_block(self.rpc.get_block_hash(number).await.map_err(map_rpc_err)?)
        .await
        .map_err(map_rpc_err)?,
    )
  }

  async fn get_outputs(&self, block: &Block, key: EdwardsPoint) -> Vec<Output> {
    let outputs = loop {
      match Self::scanner(key).scan(&self.rpc, block).await {
        Ok(outputs) => break outputs,
        Err(e) => {
          log::error!("couldn't scan block {}: {e:?}", hex::encode(block.id()));
          sleep(Duration::from_secs(60)).await;
          continue;
        }
      }
    };

    let mut txs = outputs
      .iter()
      .filter_map(|outputs| Some(outputs.not_locked()).filter(|outputs| !outputs.is_empty()))
      .collect::<Vec<_>>();

    // This should be pointless as we shouldn't be able to scan for any other subaddress
    // This just ensures nothing invalid makes it through
    for tx_outputs in &txs {
      for output in tx_outputs {
        assert!([EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARD_SUBADDRESS]
          .contains(&output.output.metadata.subaddress));
      }
    }

    let mut outputs = Vec::with_capacity(txs.len());
    for mut tx_outputs in txs.drain(..) {
      for output in tx_outputs.drain(..) {
        let mut data = output.arbitrary_data().first().cloned().unwrap_or(vec![]);

        // The Output serialization code above uses u16 to represent length
        data.truncate(u16::MAX.into());
        // Monero data segments should be <= 255 already, and MAX_DATA_LEN is currently 512
        // This just allows either Monero to change, or MAX_DATA_LEN to change, without introducing
        // complicationso
        data.truncate(MAX_DATA_LEN.try_into().unwrap());

        outputs.push(Output(output, data));
      }
    }

    outputs
  }

  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Eventuality>,
    block: &Block,
  ) -> HashMap<[u8; 32], (usize, [u8; 32], Transaction)> {
    let mut res = HashMap::new();
    if eventualities.map.is_empty() {
      return res;
    }

    async fn check_block(
      network: &Monero,
      eventualities: &mut EventualitiesTracker<Eventuality>,
      block: &Block,
      res: &mut HashMap<[u8; 32], (usize, [u8; 32], Transaction)>,
    ) {
      for hash in &block.txs {
        let tx = {
          let mut tx;
          while {
            tx = network.rpc.get_transaction(*hash).await;
            tx.is_err()
          } {
            log::error!("couldn't get transaction {}: {}", hex::encode(hash), tx.err().unwrap());
            sleep(Duration::from_secs(60)).await;
          }
          tx.unwrap()
        };

        if let Some((_, eventuality)) = eventualities.map.get(&tx.prefix.extra) {
          if eventuality.matches(&tx) {
            res.insert(
              eventualities.map.remove(&tx.prefix.extra).unwrap().0,
              (usize::try_from(block.number().unwrap()).unwrap(), tx.id(), tx),
            );
          }
        }
      }

      eventualities.block_number += 1;
      assert_eq!(eventualities.block_number, usize::try_from(block.number().unwrap()).unwrap());
    }

    for block_num in
      (eventualities.block_number + 1) .. usize::try_from(block.number().unwrap()).unwrap()
    {
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

      check_block(self, eventualities, &block, &mut res).await;
    }

    // Also check the current block
    check_block(self, eventualities, block, &mut res).await;
    assert_eq!(eventualities.block_number, usize::try_from(block.number().unwrap()).unwrap());

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
        .make_signable_transaction(block_number, &[0; 32], inputs, payments, change, true)
        .await?
        .map(|(_, signable)| signable.fee()),
    )
  }

  async fn signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    _key: EdwardsPoint,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    (): &(),
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError> {
    Ok(
      self
        .make_signable_transaction(block_number, plan_id, inputs, payments, change, false)
        .await?
        .map(|(transcript, signable)| {
          let signable = SignableTransaction { transcript, actual: signable };
          let eventuality = signable.actual.eventuality().unwrap();
          (signable, eventuality)
        }),
    )
  }

  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    match transaction.actual.clone().multisig(&keys, transaction.transcript) {
      Ok(machine) => Ok(machine),
      Err(e) => panic!("failed to create a multisig machine for TX: {e}"),
    }
  }

  async fn publish_completion(&self, tx: &Transaction) -> Result<(), NetworkError> {
    match self.rpc.publish_transaction(tx).await {
      Ok(()) => Ok(()),
      Err(RpcError::ConnectionError(e)) => {
        log::debug!("Monero ConnectionError: {e}");
        Err(NetworkError::ConnectionError)?
      }
      // TODO: Distinguish already in pool vs double spend (other signing attempt succeeded) vs
      // invalid transaction
      Err(e) => panic!("failed to publish TX {}: {e}", hex::encode(tx.hash())),
    }
  }

  async fn confirm_completion(
    &self,
    eventuality: &Eventuality,
    id: &[u8; 32],
  ) -> Result<Option<Transaction>, NetworkError> {
    let tx = self.rpc.get_transaction(*id).await.map_err(map_rpc_err)?;
    if eventuality.matches(&tx) {
      Ok(Some(tx))
    } else {
      Ok(None)
    }
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block(*id).await.unwrap().number().unwrap().try_into().unwrap()
  }

  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    claim: &[u8; 32],
  ) -> bool {
    return eventuality.matches(&self.rpc.get_transaction(*claim).await.unwrap());
  }

  #[cfg(test)]
  async fn get_transaction_by_eventuality(
    &self,
    block: usize,
    eventuality: &Eventuality,
  ) -> Transaction {
    let block = self.rpc.get_block_by_number(block).await.unwrap();
    for tx in &block.txs {
      let tx = self.rpc.get_transaction(*tx).await.unwrap();
      if eventuality.matches(&tx) {
        return tx;
      }
    }
    panic!("block didn't have a transaction for this eventuality")
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    // https://github.com/serai-dex/serai/issues/198
    sleep(std::time::Duration::from_millis(100)).await;

    #[derive(Debug, serde::Deserialize)]
    struct EmptyResponse {}
    let _: EmptyResponse = self
      .rpc
      .rpc_call(
        "json_rpc",
        Some(serde_json::json!({
          "method": "generateblocks",
          "params": {
            "wallet_address": Self::test_address().to_string(),
            "amount_of_blocks": 1
          },
        })),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    use zeroize::Zeroizing;
    use rand_core::OsRng;
    use monero_serai::wallet::FeePriority;

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    for _ in 0 .. 80 {
      self.mine_block().await;
    }

    let outputs = Self::test_scanner()
      .scan(&self.rpc, &self.rpc.get_block_by_number(new_block).await.unwrap())
      .await
      .unwrap()
      .swap_remove(0)
      .ignore_timelock();

    let amount = outputs[0].commitment().amount;
    // The dust should always be sufficient for the fee
    let fee = Monero::DUST;

    let protocol = self.rpc.get_protocol().await.unwrap();

    let decoys = Decoys::fingerprintable_canonical_select(
      &mut OsRng,
      &self.rpc,
      protocol.ring_len(),
      self.rpc.get_height().await.unwrap(),
      &outputs,
    )
    .await
    .unwrap();

    let inputs = outputs.into_iter().zip(decoys).collect::<Vec<_>>();

    let tx = MSignableTransaction::new(
      protocol,
      None,
      inputs,
      vec![(address.into(), amount - fee)],
      &Change::fingerprintable(Some(Self::test_address().into())),
      vec![],
      self.rpc.get_fee(protocol, FeePriority::Unimportant).await.unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &Zeroizing::new(Scalar::ONE.0))
    .unwrap();

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.publish_transaction(&tx).await.unwrap();
    for _ in 0 .. 10 {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}

impl UtxoNetwork for Monero {
  // wallet2 will not create a transaction larger than 100kb, and Monero won't relay a transaction
  // larger than 150kb. This fits within the 100kb mark
  // Technically, it can be ~124, yet a small bit of buffer is appreciated
  // TODO: Test creating a TX this big
  const MAX_INPUTS: usize = 120;
}
