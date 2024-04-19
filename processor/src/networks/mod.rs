use core::{fmt::Debug, time::Duration};
use std::{io, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{
  curve::{Ciphersuite, Curve},
  ThresholdKeys,
  sign::PreprocessMachine,
};

use serai_client::primitives::{NetworkId, Balance};

use log::error;

use tokio::time::sleep;

#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "bitcoin")]
pub use self::bitcoin::Bitcoin;

#[cfg(feature = "ethereum")]
pub mod ethereum;
#[cfg(feature = "ethereum")]
pub use ethereum::Ethereum;

#[cfg(feature = "monero")]
pub mod monero;
#[cfg(feature = "monero")]
pub use monero::Monero;

use crate::{Payment, Plan, multisigs::scheduler::Scheduler};

#[derive(Clone, Copy, Error, Debug)]
pub enum NetworkError {
  #[error("failed to connect to network daemon")]
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

  // Forwarded output from the prior multisig
  Forwarded,
}

impl OutputType {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&[match self {
      OutputType::External => 0,
      OutputType::Branch => 1,
      OutputType::Change => 2,
      OutputType::Forwarded => 3,
    }])
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(match byte[0] {
      0 => OutputType::External,
      1 => OutputType::Branch,
      2 => OutputType::Change,
      3 => OutputType::Forwarded,
      _ => Err(io::Error::other("invalid OutputType"))?,
    })
  }
}

pub trait Output<N: Network>: Send + Sync + Sized + Clone + PartialEq + Eq + Debug {
  type Id: 'static + Id;

  fn kind(&self) -> OutputType;

  fn id(&self) -> Self::Id;
  fn tx_id(&self) -> <N::Transaction as Transaction<N>>::Id; // TODO: Review use of
  fn key(&self) -> <N::Curve as Ciphersuite>::G;

  fn presumed_origin(&self) -> Option<N::Address>;

  fn balance(&self) -> Balance;
  fn data(&self) -> &[u8];

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
}

#[async_trait]
pub trait Transaction<N: Network>: Send + Sync + Sized + Clone + PartialEq + Debug {
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
  // TODO: Move to Balance
  #[cfg(test)]
  async fn fee(&self, network: &N) -> u64;
}

pub trait SignableTransaction: Send + Sync + Clone + Debug {
  // TODO: Move to Balance
  fn fee(&self) -> u64;
}

pub trait Eventuality: Send + Sync + Clone + PartialEq + Debug {
  type Claim: Send + Sync + Clone + PartialEq + Default + AsRef<[u8]> + AsMut<[u8]> + Debug;
  type Completion: Send + Sync + Clone + PartialEq + Debug;

  fn lookup(&self) -> Vec<u8>;

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  fn serialize(&self) -> Vec<u8>;

  fn claim(completion: &Self::Completion) -> Self::Claim;

  // TODO: Make a dedicated Completion trait
  fn serialize_completion(completion: &Self::Completion) -> Vec<u8>;
  fn read_completion<R: io::Read>(reader: &mut R) -> io::Result<Self::Completion>;
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

#[async_trait]
pub trait Block<N: Network>: Send + Sync + Sized + Clone + Debug {
  // This is currently bounded to being 32 bytes.
  type Id: 'static + Id;
  fn id(&self) -> Self::Id;
  fn parent(&self) -> Self::Id;
  /// The monotonic network time at this block.
  ///
  /// This call is presumed to be expensive and should only be called sparingly.
  async fn time(&self, rpc: &N) -> u64;
}

// The post-fee value of an expected branch.
pub struct PostFeeBranch {
  pub expected: u64,
  pub actual: Option<u64>,
}

// Return the PostFeeBranches needed when dropping a transaction
fn drop_branches<N: Network>(
  key: <N::Curve as Ciphersuite>::G,
  payments: &[Payment<N>],
) -> Vec<PostFeeBranch> {
  let mut branch_outputs = vec![];
  for payment in payments {
    if Some(&payment.address) == N::branch_address(key).as_ref() {
      branch_outputs.push(PostFeeBranch { expected: payment.balance.amount.0, actual: None });
    }
  }
  branch_outputs
}

pub struct PreparedSend<N: Network> {
  /// None for the transaction if the SignableTransaction was dropped due to lack of value.
  pub tx: Option<(N::SignableTransaction, N::Eventuality)>,
  pub post_fee_branches: Vec<PostFeeBranch>,
  /// The updated operating costs after preparing this transaction.
  pub operating_costs: u64,
}

#[async_trait]
pub trait Network: 'static + Send + Sync + Clone + PartialEq + Debug {
  /// The elliptic curve used for this network.
  type Curve: Curve;

  /// The type representing the transaction for this network.
  type Transaction: Transaction<Self>; // TODO: Review use of
  /// The type representing the block for this network.
  type Block: Block<Self>;

  /// The type containing all information on a scanned output.
  // This is almost certainly distinct from the network's native output type.
  type Output: Output<Self>;
  /// The type containing all information on a planned transaction, waiting to be signed.
  type SignableTransaction: SignableTransaction;
  /// The type containing all information to check if a plan was completed.
  ///
  /// This must be binding to both the outputs expected and the plan ID.
  type Eventuality: Eventuality;
  /// The FROST machine to sign a transaction.
  type TransactionMachine: PreprocessMachine<
    Signature = <Self::Eventuality as Eventuality>::Completion,
  >;

  /// The scheduler for this network.
  type Scheduler: Scheduler<Self>;

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

  /// Network ID for this network.
  const NETWORK: NetworkId;
  /// String ID for this network.
  const ID: &'static str;
  /// The estimated amount of time a block will take.
  const ESTIMATED_BLOCK_TIME_IN_SECONDS: usize;
  /// The amount of confirmations required to consider a block 'final'.
  const CONFIRMATIONS: usize;
  /// The maximum amount of outputs which will fit in a TX.
  /// This should be equal to MAX_INPUTS unless one is specifically limited.
  /// A TX with MAX_INPUTS and MAX_OUTPUTS must not exceed the max size.
  const MAX_OUTPUTS: usize;

  /// Minimum output value which will be handled.
  ///
  /// For any received output, there's the cost to spend the output. This value MUST exceed the
  /// cost to spend said output, and should by a notable margin (not just 2x, yet an order of
  /// magnitude).
  // TODO: Dust needs to be diversified per Coin
  const DUST: u64;

  /// The cost to perform input aggregation with a 2-input 1-output TX.
  const COST_TO_AGGREGATE: u64;

  /// Tweak keys for this network.
  fn tweak_keys(key: &mut ThresholdKeys<Self::Curve>);

  /// Address for the given group key to receive external coins to.
  #[cfg(test)]
  async fn external_address(&self, key: <Self::Curve as Ciphersuite>::G) -> Self::Address;
  /// Address for the given group key to use for scheduled branches.
  fn branch_address(key: <Self::Curve as Ciphersuite>::G) -> Option<Self::Address>;
  /// Address for the given group key to use for change.
  fn change_address(key: <Self::Curve as Ciphersuite>::G) -> Option<Self::Address>;
  /// Address for forwarded outputs from prior multisigs.
  ///
  /// forward_address must only return None if explicit forwarding isn't necessary.
  fn forward_address(key: <Self::Curve as Ciphersuite>::G) -> Option<Self::Address>;

  /// Get the latest block's number.
  async fn get_latest_block_number(&self) -> Result<usize, NetworkError>;
  /// Get a block by its number.
  async fn get_block(&self, number: usize) -> Result<Self::Block, NetworkError>;

  /// Get the latest block's number, retrying until success.
  async fn get_latest_block_number_with_retries(&self) -> usize {
    loop {
      match self.get_latest_block_number().await {
        Ok(number) => {
          return number;
        }
        Err(e) => {
          error!(
            "couldn't get the latest block number in the with retry get_latest_block_number: {e:?}",
          );
          sleep(Duration::from_secs(10)).await;
        }
      }
    }
  }

  /// Get a block, retrying until success.
  async fn get_block_with_retries(&self, block_number: usize) -> Self::Block {
    loop {
      match self.get_block(block_number).await {
        Ok(block) => {
          return block;
        }
        Err(e) => {
          error!("couldn't get block {block_number} in the with retry get_block: {:?}", e);
          sleep(Duration::from_secs(10)).await;
        }
      }
    }
  }

  /// Get the outputs within a block for a specific key.
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Ciphersuite>::G,
  ) -> Vec<Self::Output>;

  /// Get the registered eventualities completed within this block, and any prior blocks which
  /// registered eventualities may have been completed in.
  ///
  /// This may panic if not fed a block greater than the tracker's block number.
  ///
  /// Plan ID -> (block number, TX ID, completion)
  // TODO: get_eventuality_completions_internal + provided get_eventuality_completions for common
  // code
  // TODO: Consider having this return the Transaction + the Completion?
  // Or Transaction with extract_completion?
  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Self::Eventuality>,
    block: &Self::Block,
  ) -> HashMap<
    [u8; 32],
    (
      usize,
      <Self::Transaction as Transaction<Self>>::Id,
      <Self::Eventuality as Eventuality>::Completion,
    ),
  >;

  /// Returns the needed fee to fulfill this Plan at this fee rate.
  ///
  /// Returns None if this Plan isn't fulfillable (such as when the fee exceeds the input value).
  async fn needed_fee(
    &self,
    block_number: usize,
    inputs: &[Self::Output],
    payments: &[Payment<Self>],
    change: &Option<Self::Address>,
  ) -> Result<Option<u64>, NetworkError>;

  /// Create a SignableTransaction for the given Plan.
  ///
  /// The expected flow is:
  /// 1) Call needed_fee
  /// 2) If the Plan is fulfillable, amortize the fee
  /// 3) Call signable_transaction *which MUST NOT return None if the above was done properly*
  ///
  /// This takes a destructured Plan as some of these arguments are malleated from the original
  /// Plan.
  // TODO: Explicit AmortizedPlan?
  #[allow(clippy::too_many_arguments)]
  async fn signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    key: <Self::Curve as Ciphersuite>::G,
    inputs: &[Self::Output],
    payments: &[Payment<Self>],
    change: &Option<Self::Address>,
    scheduler_addendum: &<Self::Scheduler as Scheduler<Self>>::Addendum,
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError>;

  /// Prepare a SignableTransaction for a transaction.
  ///
  /// This must not persist anything as we will prepare Plans we never intend to execute.
  async fn prepare_send(
    &self,
    block_number: usize,
    plan: Plan<Self>,
    operating_costs: u64,
  ) -> Result<PreparedSend<Self>, NetworkError> {
    // Sanity check this has at least one output planned
    assert!((!plan.payments.is_empty()) || plan.change.is_some());

    let plan_id = plan.id();
    let Plan { key, inputs, mut payments, change, scheduler_addendum } = plan;
    let theoretical_change_amount =
      inputs.iter().map(|input| input.balance().amount.0).sum::<u64>() -
        payments.iter().map(|payment| payment.balance.amount.0).sum::<u64>();

    let Some(tx_fee) = self.needed_fee(block_number, &inputs, &payments, &change).await? else {
      // This Plan is not fulfillable
      // TODO: Have Plan explicitly distinguish payments and branches in two separate Vecs?
      return Ok(PreparedSend {
        tx: None,
        // Have all of its branches dropped
        post_fee_branches: drop_branches(key, &payments),
        // This plan expects a change output valued at sum(inputs) - sum(outputs)
        // Since we can no longer create this change output, it becomes an operating cost
        // TODO: Look at input restoration to reduce this operating cost
        operating_costs: operating_costs +
          if change.is_some() { theoretical_change_amount } else { 0 },
      });
    };

    // Amortize the fee over the plan's payments
    let (post_fee_branches, mut operating_costs) = (|| {
      // If we're creating a change output, letting us recoup coins, amortize the operating costs
      // as well
      let total_fee = tx_fee + if change.is_some() { operating_costs } else { 0 };

      let original_outputs = payments.iter().map(|payment| payment.balance.amount.0).sum::<u64>();
      // If this isn't enough for the total fee, drop and move on
      if original_outputs < total_fee {
        let mut remaining_operating_costs = operating_costs;
        if change.is_some() {
          // Operating costs increase by the TX fee
          remaining_operating_costs += tx_fee;
          // Yet decrease by the payments we managed to drop
          remaining_operating_costs = remaining_operating_costs.saturating_sub(original_outputs);
        }
        return (drop_branches(key, &payments), remaining_operating_costs);
      }

      let initial_payment_amounts =
        payments.iter().map(|payment| payment.balance.amount.0).collect::<Vec<_>>();

      // Amortize the transaction fee across outputs
      let mut remaining_fee = total_fee;
      // Run as many times as needed until we can successfully subtract this fee
      while remaining_fee != 0 {
        // This shouldn't be a / by 0 as these payments have enough value to cover the fee
        let this_iter_fee = remaining_fee / u64::try_from(payments.len()).unwrap();
        let mut overage = remaining_fee % u64::try_from(payments.len()).unwrap();
        for payment in &mut payments {
          let this_payment_fee = this_iter_fee + overage;
          // Only subtract the overage once
          overage = 0;

          let subtractable = payment.balance.amount.0.min(this_payment_fee);
          remaining_fee -= subtractable;
          payment.balance.amount.0 -= subtractable;
        }
      }

      // If any payment is now below the dust threshold, set its value to 0 so it'll be dropped
      for payment in &mut payments {
        if payment.balance.amount.0 < Self::DUST {
          payment.balance.amount.0 = 0;
        }
      }

      // Note the branch outputs' new values
      let mut branch_outputs = vec![];
      for (initial_amount, payment) in initial_payment_amounts.into_iter().zip(&payments) {
        if Some(&payment.address) == Self::branch_address(key).as_ref() {
          branch_outputs.push(PostFeeBranch {
            expected: initial_amount,
            actual: if payment.balance.amount.0 == 0 {
              None
            } else {
              Some(payment.balance.amount.0)
            },
          });
        }
      }

      // Drop payments now worth 0
      payments = payments
        .drain(..)
        .filter(|payment| {
          if payment.balance.amount.0 != 0 {
            true
          } else {
            log::debug!("dropping dust payment from plan {}", hex::encode(plan_id));
            false
          }
        })
        .collect();

      // Sanity check the fee was successfully amortized
      let new_outputs = payments.iter().map(|payment| payment.balance.amount.0).sum::<u64>();
      assert!((new_outputs + total_fee) <= original_outputs);

      (
        branch_outputs,
        if change.is_none() {
          // If the change is None, this had no effect on the operating costs
          operating_costs
        } else {
          // Since the change is some, and we successfully amortized, the operating costs were
          // recouped
          0
        },
      )
    })();

    let Some(tx) = self
      .signable_transaction(
        block_number,
        &plan_id,
        key,
        &inputs,
        &payments,
        &change,
        &scheduler_addendum,
      )
      .await?
    else {
      panic!(
        "{}. {}: {}, {}: {:?}, {}: {:?}, {}: {:?}, {}: {}, {}: {:?}",
        "signable_transaction returned None for a TX we prior successfully calculated the fee for",
        "id",
        hex::encode(plan_id),
        "inputs",
        inputs,
        "post-amortization payments",
        payments,
        "change",
        change,
        "successfully amoritized fee",
        tx_fee,
        "scheduler's addendum",
        scheduler_addendum,
      )
    };

    if change.is_some() {
      let on_chain_expected_change =
        inputs.iter().map(|input| input.balance().amount.0).sum::<u64>() -
          payments.iter().map(|payment| payment.balance.amount.0).sum::<u64>() -
          tx_fee;
      // If the change value is less than the dust threshold, it becomes an operating cost
      // This may be slightly inaccurate as dropping payments may reduce the fee, raising the
      // change above dust
      // That's fine since it'd have to be in a very precarious state AND then it's over-eager in
      // tabulating costs
      if on_chain_expected_change < Self::DUST {
        operating_costs += theoretical_change_amount;
      }
    }

    Ok(PreparedSend { tx: Some(tx), post_fee_branches, operating_costs })
  }

  /// Attempt to sign a SignableTransaction.
  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError>;

  /// Publish a completion.
  async fn publish_completion(
    &self,
    completion: &<Self::Eventuality as Eventuality>::Completion,
  ) -> Result<(), NetworkError>;

  /// Confirm a plan was completed by the specified transaction, per our bounds.
  ///
  /// Returns Err if there was an error with the confirmation methodology.
  /// Returns Ok(None) if this is not a valid completion.
  /// Returns Ok(Some(_)) with the completion if it's valid.
  async fn confirm_completion(
    &self,
    eventuality: &Self::Eventuality,
    claim: &<Self::Eventuality as Eventuality>::Claim,
  ) -> Result<Option<<Self::Eventuality as Eventuality>::Completion>, NetworkError>;

  /// Get a block's number by its ID.
  #[cfg(test)]
  async fn get_block_number(&self, id: &<Self::Block as Block<Self>>::Id) -> usize;

  /// Check an Eventuality is fulfilled by a claim.
  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    claim: &<Self::Eventuality as Eventuality>::Claim,
  ) -> bool;

  /// Get a transaction by the Eventuality it completes.
  #[cfg(test)]
  async fn get_transaction_by_eventuality(
    &self,
    block: usize,
    eventuality: &Self::Eventuality,
  ) -> Self::Transaction;

  #[cfg(test)]
  async fn mine_block(&self);

  /// Sends to the specified address.
  /// Additionally mines enough blocks so that the TX is past the confirmation depth.
  #[cfg(test)]
  async fn test_send(&self, key: Self::Address) -> Self::Block;
}

pub trait UtxoNetwork: Network {
  /// The maximum amount of inputs which will fit in a TX.
  /// This should be equal to MAX_OUTPUTS unless one is specifically limited.
  /// A TX with MAX_INPUTS and MAX_OUTPUTS must not exceed the max size.
  const MAX_INPUTS: usize;
}
