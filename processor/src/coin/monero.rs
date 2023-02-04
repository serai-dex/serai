use async_trait::async_trait;

use zeroize::Zeroizing;

#[cfg(test)]
use curve25519_dalek::scalar::Scalar;

use dalek_ff_group as dfg;
use transcript::RecommendedTranscript;
use frost::{curve::Ed25519, ThresholdKeys};

use monero_serai::{
  transaction::Transaction,
  block::Block as MBlock,
  rpc::Rpc,
  wallet::{
    ViewPair, Scanner,
    address::{Network, SubaddressIndex, AddressSpec, MoneroAddress},
    Fee, SpendableOutput, SignableTransaction as MSignableTransaction, TransactionMachine,
  },
};

use crate::{
  coin::{
    CoinError, Block as BlockTrait, OutputType, Output as OutputTrait,
    Transaction as TransactionTrait, Coin,
  },
  Plan, additional_key,
};

#[derive(Clone, Debug)]
pub struct Block([u8; 32], MBlock);
impl BlockTrait for Block {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.0
  }
}

#[derive(Clone, Debug)]
pub struct Output(SpendableOutput);
impl From<SpendableOutput> for Output {
  fn from(output: SpendableOutput) -> Output {
    Output(output)
  }
}

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

  fn amount(&self) -> u64 {
    self.0.commitment().amount
  }

  fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    SpendableOutput::read(reader).map(Output)
  }
}

impl TransactionTrait for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash()
  }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
  keys: ThresholdKeys<Ed25519>,
  transcript: RecommendedTranscript,
  // Monero height, defined as the length of the chain
  height: usize,
  actual: MSignableTransaction,
}

#[derive(Clone, Debug)]
pub struct Monero {
  pub(crate) rpc: Rpc,
}

impl Monero {
  pub async fn new(url: String) -> Monero {
    Monero { rpc: Rpc::new(url).unwrap() }
  }

  fn view_pair(spend: dfg::EdwardsPoint) -> ViewPair {
    ViewPair::new(spend.0, Zeroizing::new(additional_key::<Monero>(0).0))
  }

  fn address_internal(
    spend: dfg::EdwardsPoint,
    subaddress: Option<SubaddressIndex>,
  ) -> MoneroAddress {
    Self::view_pair(spend).address(
      Network::Mainnet,
      AddressSpec::Featured { subaddress, payment_id: None, guaranteed: true },
    )
  }

  fn scanner(spend: dfg::EdwardsPoint) -> Scanner {
    let mut scanner = Scanner::from_view(Self::view_pair(spend), None);
    debug_assert!(EXTERNAL_SUBADDRESS.is_none());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner
  }

  #[cfg(test)]
  fn test_view_pair() -> ViewPair {
    use group::Group;
    ViewPair::new(*dfg::EdwardsPoint::generator(), Zeroizing::new(Scalar::one()))
  }

  #[cfg(test)]
  fn test_scanner() -> Scanner {
    Scanner::from_view(Self::test_view_pair(), Some(std::collections::HashSet::new()))
  }

  #[cfg(test)]
  fn test_address() -> MoneroAddress {
    Self::test_view_pair().address(Network::Mainnet, AddressSpec::Standard)
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
  type TransactionMachine = TransactionMachine;

  type Address = MoneroAddress;

  const ID: &'static str = "Monero";
  const CONFIRMATIONS: usize = 10;
  // Testnet TX bb4d188a4c571f2f0de70dca9d475abc19078c10ffa8def26dd4f63ce1bcfd79 uses 146 inputs
  // while using less than 100kb of space, albeit with just 2 outputs (though outputs share a BP)
  // The TX size limit is half the contextual median block weight, where said weight is >= 300,000
  // This means any TX which fits into 150kb will be accepted by Monero
  // 128, even with 16 outputs, should fit into 100kb. Further efficiency by 192 may be viable
  // TODO: Get hard numbers and tune
  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  // Monero doesn't require/benefit from tweaking
  fn tweak_keys(_: &mut ThresholdKeys<Self::Curve>) {}

  fn address(key: dfg::EdwardsPoint) -> Self::Address {
    Self::address_internal(key, EXTERNAL_SUBADDRESS)
  }

  fn branch_address(key: dfg::EdwardsPoint) -> Self::Address {
    Self::address_internal(key, BRANCH_SUBADDRESS)
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // Monero defines height as chain length, so subtract 1 for block number
    Ok(self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)? - 1)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let hash = self.rpc.get_block_hash(number).await.map_err(|_| CoinError::ConnectionError)?;
    let block = self.rpc.get_block(hash).await.map_err(|_| CoinError::ConnectionError)?;
    Ok(Block(hash, block))
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: dfg::EdwardsPoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let mut transactions = Self::scanner(key)
      .scan(&self.rpc, &block.1)
      .await
      .map_err(|_| CoinError::ConnectionError)?
      .iter()
      .map(|outputs| outputs.not_locked())
      .collect::<Vec<_>>();

    // This should be pointless as we shouldn't be able to scan for any other subaddress
    // This just ensures nothing invalid makes it through
    for transaction in transactions.iter_mut() {
      *transaction = transaction
        .drain(..)
        .filter(|output| {
          [EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS]
            .contains(&output.output.metadata.subaddress)
        })
        .collect();
    }

    Ok(
      transactions
        .drain(..)
        .flat_map(|mut outputs| outputs.drain(..).map(Output::from).collect::<Vec<_>>())
        .collect(),
    )
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Ed25519>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut tx: Plan<Self>,
    change: dfg::EdwardsPoint,
    fee: Fee,
  ) -> Result<SignableTransaction, CoinError> {
    Ok(SignableTransaction {
      keys,
      transcript,
      height: block_number + 1,
      actual: MSignableTransaction::new(
        self.rpc.get_protocol().await.unwrap(), // TODO: Make this deterministic
        tx.inputs.drain(..).map(|input| input.0).collect(),
        tx.payments.drain(..).map(|payment| (payment.address, payment.amount)).collect(),
        if tx.change { Some(Self::address_internal(change, CHANGE_SUBADDRESS)) } else { None },
        vec![],
        fee,
      )
      .map_err(|_| CoinError::ConnectionError)?,
    })
  }

  async fn attempt_send(
    &self,
    transaction: SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError> {
    transaction
      .actual
      .clone()
      .multisig(
        &self.rpc,
        transaction.keys.clone(),
        transaction.transcript.clone(),
        transaction.height,
      )
      .await
      .map_err(|_| CoinError::ConnectionError)
  }

  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, CoinError> {
    self.rpc.publish_transaction(tx).await.map_err(|_| CoinError::ConnectionError)?;
    Ok(tx.hash().to_vec())
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    self.rpc.get_fee().await.unwrap()
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    // https://github.com/serai-dex/serai/issues/198
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

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
    let fee = 3000000000; // TODO

    let tx = MSignableTransaction::new(
      self.rpc.get_protocol().await.unwrap(),
      outputs,
      vec![(address, amount - fee)],
      Some(Self::test_address()),
      vec![],
      self.rpc.get_fee().await.unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &self.rpc, &Zeroizing::new(Scalar::one()))
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
