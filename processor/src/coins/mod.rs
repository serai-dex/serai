use core::fmt::Debug;
use std::{io, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{
  curve::{Ciphersuite, Curve},
  ThresholdKeys,
  sign::PreprocessMachine,
};

use serai_client::primitives::{NetworkId, Balance};

#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "bitcoin")]
pub use self::bitcoin::Bitcoin;

#[cfg(feature = "monero")]
pub mod monero;
#[cfg(feature = "monero")]
pub use monero::Monero;

use crate::Plan;

#[derive(Clone, Copy, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError,
}

pub trait Id:
  Send + Sync + Clone + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug
{
}
impl<I: Send + Sync + Clone + Default + PartialEq + AsRef<[u8]> + AsMut<[u8]> + Debug> Id for I {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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

  fn balance(&self) -> Balance;
  fn amount(&self) -> u64 {
    self.balance().amount.0
  }
  fn data(&self) -> &[u8];

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
}

#[async_trait]
pub trait Transaction<C: Coin>: Send + Sync + Sized + Clone + Debug {
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
  fn serialize(&self) -> Vec<u8>;

  #[cfg(test)]
  async fn fee(&self, coin: &C) -> u64;
}

pub trait Eventuality: Send + Sync + Clone + Debug {
  fn lookup(&self) -> Vec<u8>;

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  fn serialize(&self) -> Vec<u8>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EventualitiesTracker<E: Eventuality> {
  // Lookup property (input, nonce, TX extra...) -> (plan ID, eventuality)
  map: HashMap<Vec<u8>, ([u8; 32], E)>,
  // Block number we've scanned these eventualities too
  block_number: usize,
}

impl<E: Eventuality> EventualitiesTracker<E> {
  pub fn new() -> Self {
    EventualitiesTracker { map: HashMap::new(), block_number: usize::MAX }
  }

  pub fn register(&mut self, block_number: usize, id: [u8; 32], eventuality: E) {
    log::info!("registering eventuality for {}", hex::encode(id));

    let lookup = eventuality.lookup();
    if self.map.contains_key(&lookup) {
      panic!("registering an eventuality multiple times or lookup collision");
    }
    self.map.insert(lookup, (id, eventuality));
    // If our self tracker already went past this block number, set it back
    self.block_number = self.block_number.min(block_number);
  }

  pub fn drop(&mut self, id: [u8; 32]) {
    // O(n) due to the lack of a reverse lookup
    let mut found_key = None;
    for (key, value) in &self.map {
      if value.0 == id {
        found_key = Some(key.clone());
        break;
      }
    }

    if let Some(key) = found_key {
      self.map.remove(&key);
    }
  }
}

impl<E: Eventuality> Default for EventualitiesTracker<E> {
  fn default() -> Self {
    Self::new()
  }
}

pub trait Block<C: Coin>: Send + Sync + Sized + Clone + Debug {
  // This is currently bounded to being 32-bytes.
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
  fn parent(&self) -> Self::Id;
  fn time(&self) -> u64;
  fn median_fee(&self) -> C::Fee;
}

// The post-fee value of an expected branch.
pub struct PostFeeBranch {
  pub expected: u64,
  pub actual: Option<u64>,
}

// Return the PostFeeBranches needed when dropping a transaction
pub fn drop_branches<C: Coin>(plan: &Plan<C>) -> Vec<PostFeeBranch> {
  let mut branch_outputs = vec![];
  for payment in &plan.payments {
    if payment.address == C::branch_address(plan.key) {
      branch_outputs.push(PostFeeBranch { expected: payment.amount, actual: None });
    }
  }
  branch_outputs
}

// Amortize a fee over the plan's payments
pub fn amortize_fee<C: Coin>(plan: &mut Plan<C>, tx_fee: u64) -> Vec<PostFeeBranch> {
  // No payments to amortize over
  if plan.payments.is_empty() {
    return vec![];
  }

  // Amortize the transaction fee across outputs
  let payments_len = u64::try_from(plan.payments.len()).unwrap();
  // Use a formula which will round up
  let output_fee = (tx_fee + (payments_len - 1)) / payments_len;

  let mut branch_outputs = vec![];
  for payment in plan.payments.iter_mut() {
    let mut post_fee = payment.amount.checked_sub(output_fee);
    // If this is under our dust threshold, drop it
    if let Some(amount) = post_fee {
      if amount < C::DUST {
        post_fee = None;
      }
    }

    // Note the branch output, if this is one
    if payment.address == C::branch_address(plan.key) {
      branch_outputs.push(PostFeeBranch { expected: payment.amount, actual: post_fee });
    }
    payment.amount = post_fee.unwrap_or(0);
  }
  // Drop payments now worth 0
  plan.payments = plan.payments.drain(..).filter(|payment| payment.amount != 0).collect();
  branch_outputs
}

#[async_trait]
pub trait Coin: 'static + Send + Sync + Clone + PartialEq + Eq + Debug {
  /// The elliptic curve used for this coin.
  type Curve: Curve;

  /// The type representing the fee for this coin.
  // This should likely be a u64, wrapped in a type which implements appropriate fee logic.
  type Fee: Copy;

  /// The type representing the transaction for this coin.
  type Transaction: Transaction<Self>;
  /// The type representing the block for this coin.
  type Block: Block<Self>;

  /// The type containing all information on a scanned output.
  // This is almost certainly distinct from the coin's native output type.
  type Output: Output;
  /// The type containing all information on a planned transaction, waiting to be signed.
  type SignableTransaction: Send + Sync + Clone + Debug;
  /// The type containing all information to check if a plan was completed.
  type Eventuality: Eventuality;
  /// The FROST machine to sign a transaction.
  type TransactionMachine: PreprocessMachine<Signature = Self::Transaction>;

  /// The type representing an address.
  // This should NOT be a String, yet a tailored type representing an efficient binary encoding,
  // as detailed in the integration documentation.
  type Address: Send
    + Sync
    + Clone
    + PartialEq
    + Eq
    + Debug
    + ToString
    + TryInto<Vec<u8>>
    + TryFrom<Vec<u8>>;

  /// Network ID for this coin.
  const NETWORK: NetworkId;
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

  /// Minimum output value which will be handled.
  const DUST: u64;

  /// Tweak keys for this coin.
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

  /// Get the registered eventualities completed within this block, and any prior blocks which
  /// registered eventualities may have been completed in.
  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Self::Eventuality>,
    block: &Self::Block,
  ) -> HashMap<[u8; 32], <Self::Transaction as Transaction<Self>>::Id>;

  /// Prepare a SignableTransaction for a transaction.
  /// Returns None for the transaction if the SignableTransaction was dropped due to lack of value.
  #[rustfmt::skip]
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    block_number: usize,
    plan: Plan<Self>,
    fee: Self::Fee,
  ) -> Result<
    (Option<(Self::SignableTransaction, Self::Eventuality)>, Vec<PostFeeBranch>),
    CoinError
  >;

  /// Attempt to sign a SignableTransaction.
  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError>;

  /// Publish a transaction.
  async fn publish_transaction(&self, tx: &Self::Transaction) -> Result<(), CoinError>;

  /// Get a transaction by its ID.
  async fn get_transaction(
    &self,
    id: &<Self::Transaction as Transaction<Self>>::Id,
  ) -> Result<Self::Transaction, CoinError>;

  /// Confirm a plan was completed by the specified transaction.
  // This is allowed to take shortcuts.
  // This may assume an honest multisig, solely checking the inputs specified were spent.
  // This may solely check the outputs are equivalent *so long as it's locked to the plan ID*.
  fn confirm_completion(&self, eventuality: &Self::Eventuality, tx: &Self::Transaction) -> bool;

  /// Get a block's number by its ID.
  #[cfg(test)]
  async fn get_block_number(&self, id: &<Self::Block as Block<Self>>::Id) -> usize;

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee;

  #[cfg(test)]
  async fn mine_block(&self);

  /// Sends to the specified address.
  /// Additionally mines enough blocks so that the TX is past the confirmation depth.
  #[cfg(test)]
  async fn test_send(&self, key: Self::Address) -> Self::Block;
}
