use core::fmt::Debug;
use std::io;

use async_trait::async_trait;
use thiserror::Error;

use transcript::RecommendedTranscript;
use frost::{
  curve::{Ciphersuite, Curve},
  ThresholdKeys,
  sign::PreprocessMachine,
};

pub mod bitcoin;
pub use self::bitcoin::Bitcoin;

pub mod monero;
pub use monero::Monero;

use crate::Plan;

#[derive(Clone, Copy, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError,
  #[error("not enough funds")] // TODO: Remove this
  NotEnoughFunds,
}

pub trait Id:
  Send + Sync + Clone + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug
{
}
impl<I: Send + Sync + Clone + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug> Id for I {}

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

impl OutputType {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&[match self {
      OutputType::External => 0,
      OutputType::Branch => 1,
      OutputType::Change => 2,
    }])
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(match byte[0] {
      0 => OutputType::External,
      1 => OutputType::Branch,
      2 => OutputType::Change,
      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid OutputType"))?,
    })
  }
}

pub trait Output: Send + Sync + Sized + Clone + PartialEq + Eq + Debug {
  type Id: 'static + Id;

  fn kind(&self) -> OutputType;

  fn id(&self) -> Self::Id;
  fn amount(&self) -> u64;

  fn serialize(&self) -> Vec<u8>;
  fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

pub trait Transaction: Send + Sync + Sized + Clone + Debug {
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
}

#[async_trait]
pub trait Coin: 'static + Send + Sync + Clone + PartialEq + Eq + Debug {
  /// The elliptic curve used for this coin.
  type Curve: Send + Curve;

  /// The type representing the fee for this coin.
  // This should likely be a u64, wrapped in a type which implements appropriate fee logic.
  type Fee: Copy;

  /// The type representing the transaction for this coin.
  type Transaction: Transaction;
  /// The type representing the block for this coin.
  type Block: Block;

  /// The type containing all information on a scanned output.
  // This is almost certainly distinct from the coin's native output type.
  type Output: Output;
  /// The type containing all information on a planned transaction, waiting to be signed.
  type SignableTransaction: Send + Sync + Clone + Debug;
  /// The FROST machine to sign a transaction.
  type TransactionMachine: PreprocessMachine<Signature = Self::Transaction>;

  /// The type representing an address.
  // This should NOT be a String, yet a tailored type representing an efficient binary encoding,
  // as detailed in the integration documentation.
  type Address: Send + Sync + Clone + PartialEq + Eq + Debug;

  /// String ID for this coin.
  const ID: &'static str;
  /// The amount of confirmations required to consider a block 'final'.
  const CONFIRMATIONS: usize;
  /// The maximum amount of inputs which will fit in a TX.
  /// This should be equal to MAX_OUTPUTS unless one is specifically limited.
  /// A TX with MAX_INPUTS and MAX_OUTPUTS must not exceed the max size.
  const MAX_INPUTS: usize;
  /// The maximum amount of outputs which will fit in a TX.
  /// This should be equal to MAX_INPUTS unless one is specifically limited.
  /// A TX with MAX_INPUTS and MAX_OUTPUTS must not exceed the max size.
  const MAX_OUTPUTS: usize;

  fn tweak_keys(key: &mut ThresholdKeys<Self::Curve>);

  /// Address for the given group key to receive external coins to.
  fn address(key: <Self::Curve as Ciphersuite>::G) -> Self::Address;
  /// Address for the given group key to use for scheduled branches.
  // This is purely used for debugging purposes. Any output may be used to execute a branch.
  fn branch_address(key: <Self::Curve as Ciphersuite>::G) -> Self::Address;

  /// Get the latest block's number.
  async fn get_latest_block_number(&self) -> Result<usize, CoinError>;
  /// Get a block by its number.
  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError>;
  /// Get the outputs within a block for a specific key.
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Ciphersuite>::G,
  ) -> Result<Vec<Self::Output>, CoinError>;

  /// Prepare a SignableTransaction for a transaction.
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transcript: RecommendedTranscript,
    block_number: usize,
    tx: Plan<Self>,
    change: <Self::Curve as Ciphersuite>::G,
    fee: Self::Fee,
  ) -> Result<Self::SignableTransaction, CoinError>;

  /// Attempt to sign a SignableTransaction.
  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError>;

  /// Publish a transaction.
  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, CoinError>;

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee;

  #[cfg(test)]
  async fn mine_block(&self);

  /// Sends to the specified address.
  /// Additionally mines enough blocks so that the TX is past the confirmation depth.
  #[cfg(test)]
  async fn test_send(&self, key: Self::Address) -> Self::Block;
}
