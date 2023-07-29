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
  transaction::Transaction,
  block::Block,
  rpc::{RpcError, HttpRpc, Rpc},
  wallet::{
    ViewPair, Scanner,
    address::{Network, SubaddressIndex, AddressSpec},
    Fee, SpendableOutput, Change, Decoys, TransactionError,
    SignableTransaction as MSignableTransaction, Eventuality, TransactionMachine,
  },
};

use tokio::time::sleep;

pub use serai_client::{
  primitives::{MAX_DATA_LEN, Coin as SeraiCoin, NetworkId, Amount, Balance},
  coins::monero::Address,
};

use crate::{
  Payment, Plan, additional_key,
  coins::{
    CoinError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, Eventuality as EventualityTrait, EventualitiesTracker,
    PostFeeBranch, Coin, drop_branches, amortize_fee,
  },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output(SpendableOutput, Vec<u8>);

const EXTERNAL_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(0, 0);
const BRANCH_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(1, 0);
const CHANGE_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(2, 0);

impl OutputTrait for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While we already are immune, thanks to using featured address, this doesn't hurt and is
  // technically more efficient.
  type Id = [u8; 32];

  fn kind(&self) -> OutputType {
    match self.0.output.metadata.subaddress {
      EXTERNAL_SUBADDRESS => OutputType::External,
      BRANCH_SUBADDRESS => OutputType::Branch,
      CHANGE_SUBADDRESS => OutputType::Change,
      _ => panic!("unrecognized address was scanned for"),
    }
  }

  fn id(&self) -> Self::Id {
    self.0.output.data.key.compress().to_bytes()
  }

  fn balance(&self) -> Balance {
    Balance { coin: SeraiCoin::Monero, amount: Amount(self.0.commitment().amount) }
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
  fn serialize(&self) -> Vec<u8> {
    self.serialize()
  }
  #[cfg(test)]
  async fn fee(&self, _: &Monero) -> u64 {
    self.rct_signatures.base.fee
  }
}

impl EventualityTrait for Eventuality {
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
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Ed25519>,
  transcript: RecommendedTranscript,
  actual: MSignableTransaction,
}

impl BlockTrait<Monero> for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash()
  }

  fn parent(&self) -> Self::Id {
    self.header.previous
  }

  fn time(&self) -> u64 {
    self.header.timestamp
  }

  fn median_fee(&self) -> Fee {
    // TODO
    Fee { per_weight: 80000, mask: 10000 }
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

impl Monero {
  pub fn new(url: String) -> Monero {
    Monero { rpc: HttpRpc::new(url).unwrap() }
  }

  fn view_pair(spend: EdwardsPoint) -> ViewPair {
    ViewPair::new(spend.0, Zeroizing::new(additional_key::<Monero>(0).0))
  }

  fn address_internal(spend: EdwardsPoint, subaddress: Option<SubaddressIndex>) -> Address {
    Address::new(Self::view_pair(spend).address(
      Network::Mainnet,
      AddressSpec::Featured { subaddress, payment_id: None, guaranteed: true },
    ))
    .unwrap()
  }

  fn scanner(spend: EdwardsPoint) -> Scanner {
    let mut scanner = Scanner::from_view(Self::view_pair(spend), None);
    debug_assert!(EXTERNAL_SUBADDRESS.is_none());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner
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
    Address::new(Self::test_view_pair().address(Network::Mainnet, AddressSpec::Standard)).unwrap()
  }
}

#[async_trait]
impl Coin for Monero {
  type Curve = Ed25519;

  type Fee = Fee;
  type Transaction = Transaction;
  type Block = Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type Eventuality = Eventuality;
  type TransactionMachine = TransactionMachine;

  type Address = Address;

  const NETWORK: NetworkId = NetworkId::Monero;
  const ID: &'static str = "Monero";
  const CONFIRMATIONS: usize = 10;

  // wallet2 will not create a transaction larger than 100kb, and Monero won't relay a transaction
  // larger than 150kb. This fits within the 100kb mark
  // Technically, it can be ~124, yet a small bit of buffer is appreciated
  // TODO: Test creating a TX this big
  const MAX_INPUTS: usize = 120;
  const MAX_OUTPUTS: usize = 16;

  // 0.01 XMR
  const DUST: u64 = 10000000000;

  // Monero doesn't require/benefit from tweaking
  fn tweak_keys(_: &mut ThresholdKeys<Self::Curve>) {}

  fn address(key: EdwardsPoint) -> Self::Address {
    Self::address_internal(key, EXTERNAL_SUBADDRESS)
  }

  fn branch_address(key: EdwardsPoint) -> Self::Address {
    Self::address_internal(key, BRANCH_SUBADDRESS)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // Monero defines height as chain length, so subtract 1 for block number
    Ok(self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)? - 1)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    Ok(
      self
        .rpc
        .get_block(self.rpc.get_block_hash(number).await.map_err(|_| CoinError::ConnectionError)?)
        .await
        .map_err(|_| CoinError::ConnectionError)?,
    )
  }

  async fn get_outputs(
    &self,
    block: &Block,
    key: EdwardsPoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let mut txs = Self::scanner(key)
      .scan(&self.rpc, block)
      .await
      .map_err(|_| CoinError::ConnectionError)?
      .iter()
      .filter_map(|outputs| Some(outputs.not_locked()).filter(|outputs| !outputs.is_empty()))
      .collect::<Vec<_>>();

    // This should be pointless as we shouldn't be able to scan for any other subaddress
    // This just ensures nothing invalid makes it through
    for tx_outputs in &txs {
      for output in tx_outputs {
        assert!([EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS]
          .contains(&output.output.metadata.subaddress));
      }
    }

    let mut outputs = Vec::with_capacity(txs.len());
    for mut tx_outputs in txs.drain(..) {
      for output in tx_outputs.drain(..) {
        let mut data = output.arbitrary_data().get(0).cloned().unwrap_or(vec![]);

        // The Output serialization code above uses u16 to represent length
        data.truncate(u16::MAX.into());
        // Monero data segments should be <= 255 already, and MAX_DATA_LEN is currently 512
        // This just allows either Monero to change, or MAX_DATA_LEN to change, without introducing
        // complicationso
        data.truncate(MAX_DATA_LEN.try_into().unwrap());

        outputs.push(Output(output, data));
      }
    }

    Ok(outputs)
  }

  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Eventuality>,
    block: &Block,
  ) -> HashMap<[u8; 32], [u8; 32]> {
    let mut res = HashMap::new();
    if eventualities.map.is_empty() {
      return res;
    }

    async fn check_block(
      coin: &Monero,
      eventualities: &mut EventualitiesTracker<Eventuality>,
      block: &Block,
      res: &mut HashMap<[u8; 32], [u8; 32]>,
    ) {
      for hash in &block.txs {
        let tx = {
          let mut tx;
          while {
            tx = coin.get_transaction(hash).await;
            tx.is_err()
          } {
            log::error!("couldn't get transaction {}: {}", hex::encode(hash), tx.err().unwrap());
            sleep(Duration::from_secs(60)).await;
          }
          tx.unwrap()
        };

        if let Some((_, eventuality)) = eventualities.map.get(&tx.prefix.extra) {
          if eventuality.matches(&tx) {
            res.insert(eventualities.map.remove(&tx.prefix.extra).unwrap().0, tx.hash());
          }
        }
      }

      eventualities.block_number += 1;
      assert_eq!(eventualities.block_number, block.number());
    }

    for block_num in (eventualities.block_number + 1) .. block.number() {
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
    assert_eq!(eventualities.block_number, block.number());

    res
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Ed25519>,
    block_number: usize,
    mut plan: Plan<Self>,
    fee: Fee,
  ) -> Result<(Option<(SignableTransaction, Eventuality)>, Vec<PostFeeBranch>), CoinError> {
    // Sanity check this has at least one output planned
    assert!((!plan.payments.is_empty()) || plan.change.is_some());

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
    assert_eq!(protocol, self.rpc.get_protocol().await.map_err(|_| CoinError::ConnectionError)?);

    let spendable_outputs = plan.inputs.iter().cloned().map(|input| input.0).collect::<Vec<_>>();

    let mut transcript = plan.transcript();

    // All signers need to select the same decoys
    // All signers use the same height and a seeded RNG to make sure they do so.
    let decoys = Decoys::select(
      &mut ChaCha20Rng::from_seed(transcript.rng_seed(b"decoys")),
      &self.rpc,
      protocol.ring_len(),
      block_number + 1,
      &spendable_outputs,
    )
    .await
    .map_err(|_| CoinError::ConnectionError)
    .unwrap();

    let inputs = spendable_outputs.into_iter().zip(decoys.into_iter()).collect::<Vec<_>>();

    let signable = |mut plan: Plan<Self>, tx_fee: Option<_>| {
      // Monero requires at least two outputs
      // If we only have one output planned, add a dummy payment
      let outputs = plan.payments.len() + usize::from(u8::from(plan.change.is_some()));
      if outputs == 0 {
        return Ok(None);
      } else if outputs == 1 {
        plan.payments.push(Payment {
          address: Address::new(
            ViewPair::new(EdwardsPoint::generator().0, Zeroizing::new(Scalar::ONE.0))
              .address(Network::Mainnet, AddressSpec::Standard),
          )
          .unwrap(),
          amount: 0,
          data: None,
        });
      }

      let mut payments = vec![];
      for payment in &plan.payments {
        // If we're solely estimating the fee, don't actually specify an amount
        // This won't affect the fee calculation yet will ensure we don't hit an out of funds error
        payments.push((
          payment.address.clone().into(),
          if tx_fee.is_none() { 0 } else { payment.amount },
        ));
      }

      match MSignableTransaction::new(
        protocol,
        // Use the plan ID as the r_seed
        // This perfectly binds the plan while simultaneously allowing verifying the plan was
        // executed with no additional communication
        Some(Zeroizing::new(plan.id())),
        inputs.clone(),
        payments,
        plan.change.map(|key| {
          Change::fingerprintable(Self::address_internal(key, CHANGE_SUBADDRESS).into())
        }),
        vec![],
        fee,
      ) {
        Ok(signable) => Ok(Some(signable)),
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
            if let Some(tx_fee) = tx_fee {
              panic!(
                "{}. in: {inputs}, out: {outputs}, fee: {fee}, prior estimated fee: {tx_fee}",
                "didn't have enough funds for a Monero TX",
              );
            } else {
              Ok(None)
            }
          }
          TransactionError::RpcError(e) => {
            log::error!("RpcError when preparing transaction: {e:?}");
            Err(CoinError::ConnectionError)
          }
        },
      }
    };

    let tx_fee = match signable(plan.clone(), None)? {
      Some(tx) => tx.fee(),
      None => return Ok((None, drop_branches(&plan))),
    };

    let branch_outputs = amortize_fee(&mut plan, tx_fee);

    let signable = SignableTransaction {
      keys,
      transcript,
      actual: match signable(plan, Some(tx_fee))? {
        Some(signable) => signable,
        None => return Ok((None, branch_outputs)),
      },
    };
    let eventuality = signable.actual.eventuality().unwrap();
    Ok((Some((signable, eventuality)), branch_outputs))
  }

  async fn attempt_send(
    &self,
    transaction: SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError> {
    match transaction.actual.clone().multisig(transaction.keys.clone(), transaction.transcript) {
      Ok(machine) => Ok(machine),
      Err(e) => panic!("failed to create a multisig machine for TX: {e}"),
    }
  }

  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<(), CoinError> {
    match self.rpc.publish_transaction(tx).await {
      Ok(_) => Ok(()),
      Err(RpcError::ConnectionError) => Err(CoinError::ConnectionError)?,
      // TODO: Distinguish already in pool vs double spend (other signing attempt succeeded) vs
      // invalid transaction
      Err(e) => panic!("failed to publish TX {}: {e}", hex::encode(tx.hash())),
    }
  }

  async fn get_transaction(&self, id: &[u8; 32]) -> Result<Transaction, CoinError> {
    self.rpc.get_transaction(*id).await.map_err(|_| CoinError::ConnectionError)
  }

  fn confirm_completion(&self, eventuality: &Eventuality, tx: &Transaction) -> bool {
    eventuality.matches(tx)
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block(*id).await.unwrap().number()
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    use monero_serai::wallet::FeePriority;

    self.rpc.get_fee(self.rpc.get_protocol().await.unwrap(), FeePriority::Highest).await.unwrap()
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    // https://github.com/serai-dex/serai/issues/198
    sleep(std::time::Duration::from_millis(100)).await;

    #[derive(serde::Deserialize, Debug)]
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
  async fn test_send(&self, address: Self::Address) -> Block {
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

    let decoys = Decoys::select(
      &mut OsRng,
      &self.rpc,
      protocol.ring_len(),
      self.rpc.get_height().await.unwrap() - 1,
      &outputs,
    )
    .await
    .unwrap();

    let inputs = outputs.into_iter().zip(decoys.into_iter()).collect::<Vec<_>>();

    let tx = MSignableTransaction::new(
      protocol,
      None,
      inputs,
      vec![(address.into(), amount - fee)],
      Some(Change::fingerprintable(Self::test_address().into())),
      vec![],
      self.rpc.get_fee(protocol, FeePriority::Low).await.unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &Zeroizing::new(Scalar::ONE.0))
    .await
    .unwrap();

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.publish_transaction(&tx).await.unwrap();
    for _ in 0 .. 10 {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}
