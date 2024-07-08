use std::{time::Duration, collections::HashMap, io};

use async_trait::async_trait;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};
use frost::{curve::Ed25519, ThresholdKeys};

use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{
  ringct::RctType,
  transaction::Transaction,
  block::Block,
  rpc::{FeeRate, RpcError, Rpc},
  address::{Network as MoneroNetwork, SubaddressIndex},
  ViewPair, GuaranteedViewPair, WalletOutput, OutputWithDecoys, GuaranteedScanner,
  send::{
    SendError, Change, SignableTransaction as MSignableTransaction, Eventuality, TransactionMachine,
  },
};
#[cfg(test)]
use monero_wallet::Scanner;

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
pub struct Output(WalletOutput);

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
    match self.0.subaddress() {
      EXTERNAL_SUBADDRESS => OutputType::External,
      BRANCH_SUBADDRESS => OutputType::Branch,
      CHANGE_SUBADDRESS => OutputType::Change,
      FORWARD_SUBADDRESS => OutputType::Forwarded,
      _ => panic!("unrecognized address was scanned for"),
    }
  }

  fn id(&self) -> Self::Id {
    self.0.key().compress().to_bytes()
  }

  fn tx_id(&self) -> [u8; 32] {
    self.0.transaction()
  }

  fn key(&self) -> EdwardsPoint {
    EdwardsPoint(self.0.key() - (EdwardsPoint::generator().0 * self.0.key_offset()))
  }

  fn presumed_origin(&self) -> Option<Address> {
    None
  }

  fn balance(&self) -> Balance {
    Balance { coin: Coin::Monero, amount: Amount(self.0.commitment().amount) }
  }

  fn data(&self) -> &[u8] {
    let Some(data) = self.0.arbitrary_data().first() else { return &[] };
    // If the data is too large, prune it
    // This should cause decoding the instruction to fail, and trigger a refund as appropriate
    if data.len() > usize::try_from(MAX_DATA_LEN).unwrap() {
      return &[];
    }
    data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.0.write(writer)?;
    Ok(())
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Ok(Output(WalletOutput::read(reader)?))
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
    match self {
      Transaction::V1 { .. } => panic!("v1 TX in test-only function"),
      Transaction::V2 { ref proofs, .. } => proofs.as_ref().unwrap().base.fee,
    }
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
    self.extra()
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
pub struct SignableTransaction(MSignableTransaction);
impl SignableTransactionTrait for SignableTransaction {
  fn fee(&self) -> u64 {
    self.0.necessary_fee()
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
    const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW: usize = 60;

    // If Monero doesn't have enough blocks to build a window, it doesn't define a network time
    if (self.number().unwrap() + 1) < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
      // Use the block number as the time
      return u64::try_from(self.number().unwrap()).unwrap();
    }

    let mut timestamps = vec![self.header.timestamp];
    let mut parent = self.parent();
    while timestamps.len() < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
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
    res + u64::try_from(self.number().unwrap()).unwrap()
  }
}

#[derive(Clone, Debug)]
pub struct Monero {
  rpc: SimpleRequestRpc,
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

enum MakeSignableTransactionResult {
  Fee(u64),
  SignableTransaction(MSignableTransaction),
}

impl Monero {
  pub async fn new(url: String) -> Monero {
    let mut res = SimpleRequestRpc::new(url.clone()).await;
    while let Err(e) = res {
      log::error!("couldn't connect to Monero node: {e:?}");
      tokio::time::sleep(Duration::from_secs(5)).await;
      res = SimpleRequestRpc::new(url.clone()).await;
    }
    Monero { rpc: res.unwrap() }
  }

  fn view_pair(spend: EdwardsPoint) -> GuaranteedViewPair {
    GuaranteedViewPair::new(spend.0, Zeroizing::new(additional_key::<Monero>(0).0)).unwrap()
  }

  fn address_internal(spend: EdwardsPoint, subaddress: Option<SubaddressIndex>) -> Address {
    Address::new(Self::view_pair(spend).address(MoneroNetwork::Mainnet, subaddress, None)).unwrap()
  }

  fn scanner(spend: EdwardsPoint) -> GuaranteedScanner {
    let mut scanner = GuaranteedScanner::new(Self::view_pair(spend));
    debug_assert!(EXTERNAL_SUBADDRESS.is_none());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner.register_subaddress(FORWARD_SUBADDRESS.unwrap());
    scanner
  }

  async fn median_fee(&self, block: &Block) -> Result<FeeRate, NetworkError> {
    let mut fees = vec![];
    for tx_hash in &block.transactions {
      let tx =
        self.rpc.get_transaction(*tx_hash).await.map_err(|_| NetworkError::ConnectionError)?;
      // Only consider fees from RCT transactions, else the fee property read wouldn't be accurate
      let fee = match &tx {
        Transaction::V2 { proofs: Some(proofs), .. } => proofs.base.fee,
        _ => continue,
      };
      fees.push(fee / u64::try_from(tx.weight()).unwrap());
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // TODO: Set a sane minimum fee
    const MINIMUM_FEE: u64 = 1_500_000;
    Ok(FeeRate::new(fee.max(MINIMUM_FEE), 10000).unwrap())
  }

  async fn make_signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
    calculating_fee: bool,
  ) -> Result<Option<MakeSignableTransactionResult>, NetworkError> {
    for payment in payments {
      assert_eq!(payment.balance.coin, Coin::Monero);
    }

    // TODO2: Use an fee representative of several blocks, cached inside Self
    let block_for_fee = self.get_block(block_number).await?;
    let fee_rate = self.median_fee(&block_for_fee).await?;

    // Determine the RCT proofs to make based off the hard fork
    // TODO: Make a fn for this block which is duplicated with tests
    let rct_type = match block_for_fee.header.hardfork_version {
      14 => RctType::ClsagBulletproof,
      15 | 16 => RctType::ClsagBulletproofPlus,
      _ => panic!("Monero hard forked and the processor wasn't updated for it"),
    };

    let mut transcript =
      RecommendedTranscript::new(b"Serai Processor Monero Transaction Transcript");
    transcript.append_message(b"plan", plan_id);

    // All signers need to select the same decoys
    // All signers use the same height and a seeded RNG to make sure they do so.
    let mut inputs_actual = Vec::with_capacity(inputs.len());
    for input in inputs {
      inputs_actual.push(
        OutputWithDecoys::fingerprintable_deterministic_new(
          &mut ChaCha20Rng::from_seed(transcript.rng_seed(b"decoys")),
          &self.rpc,
          // TODO: Have Decoys take RctType
          match rct_type {
            RctType::ClsagBulletproof => 11,
            RctType::ClsagBulletproofPlus => 16,
            _ => panic!("selecting decoys for an unsupported RctType"),
          },
          block_number + 1,
          input.0.clone(),
        )
        .await
        .map_err(map_rpc_err)?,
      );
    }

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
            .unwrap()
            .legacy_address(MoneroNetwork::Mainnet),
        )
        .unwrap(),
        balance: Balance { coin: Coin::Monero, amount: Amount(0) },
        data: None,
      });
    }

    let payments = payments
      .into_iter()
      .map(|payment| (payment.address.into(), payment.balance.amount.0))
      .collect::<Vec<_>>();

    match MSignableTransaction::new(
      rct_type,
      // Use the plan ID as the outgoing view key
      Zeroizing::new(*plan_id),
      inputs_actual,
      payments,
      Change::fingerprintable(change.as_ref().map(|change| change.clone().into())),
      vec![],
      fee_rate,
    ) {
      Ok(signable) => Ok(Some({
        if calculating_fee {
          MakeSignableTransactionResult::Fee(signable.necessary_fee())
        } else {
          MakeSignableTransactionResult::SignableTransaction(signable)
        }
      })),
      Err(e) => match e {
        SendError::UnsupportedRctType => {
          panic!("trying to use an RctType unsupported by monero-wallet")
        }
        SendError::NoInputs |
        SendError::InvalidDecoyQuantity |
        SendError::NoOutputs |
        SendError::TooManyOutputs |
        SendError::NoChange |
        SendError::TooMuchArbitraryData |
        SendError::TooLargeTransaction |
        SendError::WrongPrivateKey => {
          panic!("created an invalid Monero transaction: {e}");
        }
        SendError::MultiplePaymentIds => {
          panic!("multiple payment IDs despite not supporting integrated addresses");
        }
        SendError::NotEnoughFunds { inputs, outputs, necessary_fee } => {
          log::debug!(
            "Monero NotEnoughFunds. inputs: {:?}, outputs: {:?}, necessary_fee: {necessary_fee:?}",
            inputs,
            outputs
          );
          match necessary_fee {
            Some(necessary_fee) => {
              // If we're solely calculating the fee, return the fee this TX will cost
              if calculating_fee {
                Ok(Some(MakeSignableTransactionResult::Fee(necessary_fee)))
              } else {
                // If we're actually trying to make the TX, return None
                Ok(None)
              }
            }
            // We didn't have enough funds to even cover the outputs
            None => {
              // Ensure we're not misinterpreting this
              assert!(outputs > inputs);
              Ok(None)
            }
          }
        }
        SendError::MaliciousSerialization | SendError::ClsagError(_) | SendError::FrostError(_) => {
          panic!("supposedly unreachable (at this time) Monero error: {e}");
        }
      },
    }
  }

  #[cfg(test)]
  fn test_view_pair() -> ViewPair {
    ViewPair::new(*EdwardsPoint::generator(), Zeroizing::new(Scalar::ONE.0)).unwrap()
  }

  #[cfg(test)]
  fn test_scanner() -> Scanner {
    Scanner::new(Self::test_view_pair())
  }

  #[cfg(test)]
  fn test_address() -> Address {
    Address::new(Self::test_view_pair().legacy_address(MoneroNetwork::Mainnet)).unwrap()
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

    // Miner transactions are required to explicitly state their timelock, so this does exclude
    // those (which have an extended timelock we don't want to deal with)
    let raw_outputs = outputs.not_additionally_locked();
    let mut outputs = Vec::with_capacity(raw_outputs.len());
    for output in raw_outputs {
      // This should be pointless as we shouldn't be able to scan for any other subaddress
      // This just helps ensures nothing invalid makes it through
      assert!([EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARD_SUBADDRESS]
        .contains(&output.subaddress()));

      outputs.push(Output(output));
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
      for hash in &block.transactions {
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

        if let Some((_, eventuality)) = eventualities.map.get(&tx.prefix().extra) {
          if eventuality.matches(&tx) {
            res.insert(
              eventualities.map.remove(&tx.prefix().extra).unwrap().0,
              (block.number().unwrap(), tx.id(), tx),
            );
          }
        }
      }

      eventualities.block_number += 1;
      assert_eq!(eventualities.block_number, block.number().unwrap());
    }

    for block_num in (eventualities.block_number + 1) .. block.number().unwrap() {
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
    assert_eq!(eventualities.block_number, block.number().unwrap());

    res
  }

  async fn needed_fee(
    &self,
    block_number: usize,
    inputs: &[Output],
    payments: &[Payment<Self>],
    change: &Option<Address>,
  ) -> Result<Option<u64>, NetworkError> {
    let res = self
      .make_signable_transaction(block_number, &[0; 32], inputs, payments, change, true)
      .await?;
    let Some(res) = res else { return Ok(None) };
    let MakeSignableTransactionResult::Fee(fee) = res else {
      panic!("told make_signable_transaction calculating_fee and got transaction")
    };
    Ok(Some(fee))
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
    let res = self
      .make_signable_transaction(block_number, plan_id, inputs, payments, change, false)
      .await?;
    let Some(res) = res else { return Ok(None) };
    let MakeSignableTransactionResult::SignableTransaction(signable) = res else {
      panic!("told make_signable_transaction not calculating_fee and got fee")
    };

    let signable = SignableTransaction(signable);
    let eventuality = signable.0.clone().into();
    Ok(Some((signable, eventuality)))
  }

  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    match transaction.0.clone().multisig(&keys) {
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
    self.rpc.get_block(*id).await.unwrap().number().unwrap()
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
    for tx in &block.transactions {
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
    self.rpc.generate_blocks(&Self::test_address().into(), 1).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    use zeroize::Zeroizing;
    use rand_core::{RngCore, OsRng};
    use monero_wallet::rpc::FeePriority;

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    for _ in 0 .. 80 {
      self.mine_block().await;
    }

    let new_block = self.rpc.get_block_by_number(new_block).await.unwrap();
    let mut outputs =
      Self::test_scanner().scan(&self.rpc, &new_block).await.unwrap().ignore_additional_timelock();
    let output = outputs.swap_remove(0);

    let amount = output.commitment().amount;
    // The dust should always be sufficient for the fee
    let fee = Monero::DUST;

    let rct_type = match new_block.header.hardfork_version {
      14 => RctType::ClsagBulletproof,
      15 | 16 => RctType::ClsagBulletproofPlus,
      _ => panic!("Monero hard forked and the processor wasn't updated for it"),
    };

    let output = OutputWithDecoys::fingerprintable_deterministic_new(
      &mut OsRng,
      &self.rpc,
      match rct_type {
        RctType::ClsagBulletproof => 11,
        RctType::ClsagBulletproofPlus => 16,
        _ => panic!("selecting decoys for an unsupported RctType"),
      },
      self.rpc.get_height().await.unwrap(),
      output,
    )
    .await
    .unwrap();

    let mut outgoing_view_key = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(outgoing_view_key.as_mut());
    let tx = MSignableTransaction::new(
      rct_type,
      outgoing_view_key,
      vec![output],
      vec![(address.into(), amount - fee)],
      Change::fingerprintable(Some(Self::test_address().into())),
      vec![],
      self.rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
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
