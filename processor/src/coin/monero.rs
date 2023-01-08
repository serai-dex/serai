use std::collections::HashMap;

use async_trait::async_trait;

use zeroize::Zeroizing;

use curve25519_dalek::scalar::Scalar;

use dalek_ff_group as dfg;
use transcript::RecommendedTranscript;
use frost::{curve::Ed25519, ThresholdKeys};

use monero_serai::{
  transaction::Transaction,
  block::Block,
  rpc::Rpc,
  wallet::{
    ViewPair, Scanner,
    address::{Network, MoneroAddress},
    Fee, SpendableOutput, SignableTransaction as MSignableTransaction, TransactionMachine,
  },
};

use crate::{
  additional_key,
  coin::{CoinError, Output as OutputTrait, Coin},
};

#[derive(Clone, Debug)]
pub struct Output(SpendableOutput);
impl From<SpendableOutput> for Output {
  fn from(output: SpendableOutput) -> Output {
    Output(output)
  }
}

impl OutputTrait for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While the Monero library offers a variant which allows senders to ensure their TXs have unique
  // output keys, Serai can still be targeted using the classic burning bug
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
  // Monero height, defined as the length of the chain
  height: usize,
  actual: MSignableTransaction,
}

#[derive(Clone, Debug)]
pub struct Monero {
  pub(crate) rpc: Rpc,
  view: Zeroizing<Scalar>,
}

impl Monero {
  pub async fn new(url: String) -> Monero {
    Monero { rpc: Rpc::new(url).unwrap(), view: Zeroizing::new(additional_key::<Monero>(0).0) }
  }

  fn scanner(&self, spend: dfg::EdwardsPoint) -> Scanner {
    Scanner::from_view(ViewPair::new(spend.0, self.view.clone()), Network::Mainnet, None)
  }

  #[cfg(test)]
  fn empty_scanner() -> Scanner {
    use group::Group;
    Scanner::from_view(
      ViewPair::new(*dfg::EdwardsPoint::generator(), Zeroizing::new(Scalar::one())),
      Network::Mainnet,
      Some(std::collections::HashSet::new()),
    )
  }

  #[cfg(test)]
  fn empty_address() -> MoneroAddress {
    Self::empty_scanner().address()
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

  const ID: &'static [u8] = b"Monero";
  const CONFIRMATIONS: usize = 10;
  // Testnet TX bb4d188a4c571f2f0de70dca9d475abc19078c10ffa8def26dd4f63ce1bcfd79 uses 146 inputs
  // while using less than 100kb of space, albeit with just 2 outputs (though outputs share a BP)
  // The TX size limit is half the contextual median block weight, where said weight is >= 300,000
  // This means any TX which fits into 150kb will be accepted by Monero
  // 128, even with 16 outputs, should fit into 100kb. Further efficiency by 192 may be viable
  // TODO: Get hard numbers and tune
  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: dfg::EdwardsPoint) -> Self::Address {
    self.scanner(key).address()
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // Monero defines height as chain length, so subtract 1 for block number
    Ok(self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)? - 1)
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    self.rpc.get_block(number).await.map_err(|_| CoinError::ConnectionError)
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: dfg::EdwardsPoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    Ok(
      self
        .scanner(key)
        .scan(&self.rpc, block)
        .await
        .map_err(|_| CoinError::ConnectionError)?
        .iter()
        .flat_map(|outputs| outputs.not_locked())
        .map(Output::from)
        .collect(),
    )
  }

  async fn is_confirmed(&self, tx: &[u8]) -> Result<bool, CoinError> {
    let tx_block_number = self
      .rpc
      .get_transaction_block_number(tx)
      .await
      .map_err(|_| CoinError::ConnectionError)?
      .unwrap_or(usize::MAX);
    Ok((self.get_latest_block_number().await?.saturating_sub(tx_block_number) + 1) >= 10)
  }

  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Ed25519>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut inputs: Vec<Output>,
    payments: &[(MoneroAddress, u64)],
    fee: Fee,
  ) -> Result<SignableTransaction, CoinError> {
    let spend = keys.group_key();
    Ok(SignableTransaction {
      keys,
      transcript,
      height: block_number + 1,
      actual: MSignableTransaction::new(
        self.rpc.get_protocol().await.unwrap(), // TODO: Make this deterministic
        inputs.drain(..).map(|input| input.0).collect(),
        payments.to_vec(),
        Some(self.address(spend)),
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

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    self.rpc.publish_transaction(tx).await.map_err(|_| CoinError::ConnectionError)?;
    Ok((tx.hash().to_vec(), tx.prefix.outputs.iter().map(|output| output.key.to_bytes()).collect()))
  }

  fn tweak_keys<'a>(&self, keys : &'a mut HashMap<u16, ThresholdKeys<Self::Curve>>) {

  }

  fn tweak_key<'a>(&self, one_key: &'a mut ThresholdKeys<Self::Curve>) {

  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    self.rpc.get_fee().await.unwrap()
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    #[derive(serde::Deserialize, Debug)]
    struct EmptyResponse {}
    let _: EmptyResponse = self
      .rpc
      .rpc_call(
        "json_rpc",
        Some(serde_json::json!({
          "method": "generateblocks",
          "params": {
            "wallet_address": Self::empty_address().to_string(),
            "amount_of_blocks": 10
          },
        })),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    use zeroize::Zeroizing;
    use rand_core::OsRng;

    let new_block = self.get_latest_block_number().await.unwrap() + 1;

    self.mine_block().await;
    for _ in 0 .. 7 {
      self.mine_block().await;
    }

    let outputs = Self::empty_scanner()
      .scan(&self.rpc, &self.rpc.get_block(new_block).await.unwrap())
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
      Some(Self::empty_address()),
      vec![],
      self.rpc.get_fee().await.unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &self.rpc, &Zeroizing::new(Scalar::one()))
    .await
    .unwrap();
    self.rpc.publish_transaction(&tx).await.unwrap();
    self.mine_block().await;
  }
}
