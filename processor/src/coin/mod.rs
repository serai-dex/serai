use core::{marker::Send, fmt::Debug};

use async_trait::async_trait;
use thiserror::Error;

use transcript::RecommendedTranscript;
use frost::{
  curve::{Ciphersuite, Curve},
  ThresholdKeys,
  sign::PreprocessMachine,
};

pub mod monero;
pub use self::monero::Monero;

#[derive(Clone, Copy, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError,
}

pub trait Id:
  Send + Sync + Clone + Copy + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug
{
}
impl<I: Send + Sync + Clone + Copy + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug> Id
  for I
{
}

pub trait Block: Send + Sync + Sized + Clone + Debug {
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputType {
  // Needs to be processed/sent up to Substrate
  External,

  // Given a known output set, and a known series of outbound transactions, we should be able to
  // form a completely deterministic schedule S. The issue is when S has TXs which spend prior TXs
  // in S (which is needed for our logarithmic scheduling). In order to have the descendant TX, say
  // S[1], build off S[0], we need to observe when S[0] is included on-chain.
  //
  // We cannot.
  //
  // Monero (and other privacy coins) do not expose their UTXO graphs. Even if we know how to
  // create S[0], and the actual payment info behind it, we cannot observe it on the blockchain
  // unless we participated in creating it. Locking the entire schedule, when we cannot sign for
  // the entire schedule at once, to a single signing set isn't feasible.
  //
  // While any member of the active signing set can provide data enabling other signers to
  // participate, it's several KB of data which we then have to code communication for.
  // The other option is to simply not observe S[0]. Instead, observe a TX with an identical output
  // to the one in S[0] we intended to use for S[1]. It's either from S[0], or Eve, a malicious
  // actor, has sent us a forged TX which is... equally as usable? so who cares?
  //
  // The only issue is if we have multiple outputs on-chain with identical amounts and purposes.
  // Accordingly, when the scheduler makes a plan for when a specific output is available, it
  // shouldn't write that plan. It should *push* that plan to a queue of plans to perform when
  // instances of that output occur.
  Branch,

  // Should be added to the available UTXO pool with no further action
  Change,
}

pub trait Output: Send + Sync + Sized + Clone + Debug {
  type Id: 'static + Id;

  fn kind(&self) -> OutputType;

  fn id(&self) -> Self::Id;
  fn amount(&self) -> u64;

  fn serialize(&self) -> Vec<u8>;
  fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

#[async_trait]
pub trait Coin: 'static + Send + Sync + Clone + Debug {
  type Curve: Curve;

  type Fee: Copy;
  type Transaction;
  type Block: Block;

  type Output: Output;
  type SignableTransaction;
  type TransactionMachine: PreprocessMachine<Signature = Self::Transaction>;

  type Address: Send;

  const ID: &'static str;
  const CONFIRMATIONS: usize;
  const MAX_INPUTS: usize;
  const MAX_OUTPUTS: usize; // TODO: Decide if this includes change or not

  /// Address for the given group key to receive external coins to.
  // Doesn't have to take self, enables some level of caching which is pleasant
  fn address(&self, key: <Self::Curve as Ciphersuite>::G) -> Self::Address;
  /// Address for the given group key to use for scheduled branches.
  fn branch_address(&self, key: <Self::Curve as Ciphersuite>::G) -> Self::Address;

  async fn get_latest_block_number(&self) -> Result<usize, CoinError>;
  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError>;
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Ciphersuite>::G,
  ) -> Result<Vec<Self::Output>, CoinError>;

  #[allow(clippy::too_many_arguments)]
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transcript: RecommendedTranscript,
    block_number: usize,
    inputs: Vec<Self::Output>,
    payments: &[(Self::Address, u64)],
    change: Option<<Self::Curve as Ciphersuite>::G>,
    fee: Self::Fee,
  ) -> Result<Self::SignableTransaction, CoinError>;

  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError>;

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as Output>::Id>), CoinError>;

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee;

  #[cfg(test)]
  async fn mine_block(&self);

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address);
}
