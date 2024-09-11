#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use serai_primitives::{Coin, Amount};

use primitives::{ReceivedOutput, Payment};
use scanner::{ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, BlockFor};
use scheduler_primitives::*;

mod tree;
pub use tree::*;

/// A planned transaction.
pub struct PlannedTransaction<S: ScannerFeed, ST: SignableTransaction, A> {
  /// The signable transaction.
  pub signable: ST,
  /// The Eventuality to watch for.
  pub eventuality: EventualityFor<S>,
  /// The auxilliary data for this transaction.
  pub auxilliary: A,
}

/// A planned transaction which was created via amortizing the fee.
pub struct AmortizePlannedTransaction<S: ScannerFeed, ST: SignableTransaction, A> {
  /// The amounts the included payments were worth.
  ///
  /// If the payments passed as an argument are sorted from highest to lowest valued, these `n`
  /// amounts will be for the first `n` payments.
  pub effected_payments: Vec<Amount>,
  /// Whether or not the planned transaction had a change output.
  pub has_change: bool,
  /// The signable transaction.
  pub signable: ST,
  /// The Eventuality to watch for.
  pub eventuality: EventualityFor<S>,
  /// The auxilliary data for this transaction.
  pub auxilliary: A,
}

/// An object able to plan a transaction.
pub trait TransactionPlanner<S: ScannerFeed, A>: 'static + Send + Sync {
  /// The type representing a fee rate to use for transactions.
  type FeeRate: Clone + Copy;

  /// The type representing a signable transaction.
  type SignableTransaction: SignableTransaction;

  /// The maximum amount of inputs allowed in a transaction.
  const MAX_INPUTS: usize;
  /// The maximum amount of outputs allowed in a transaction, including the change output.
  const MAX_OUTPUTS: usize;

  /// Obtain the fee rate to pay.
  ///
  /// This must be constant to the block and coin.
  fn fee_rate(block: &BlockFor<S>, coin: Coin) -> Self::FeeRate;

  /// The branch address for this key of Serai's.
  fn branch_address(key: KeyFor<S>) -> AddressFor<S>;
  /// The change address for this key of Serai's.
  fn change_address(key: KeyFor<S>) -> AddressFor<S>;
  /// The forwarding address for this key of Serai's.
  fn forwarding_address(key: KeyFor<S>) -> AddressFor<S>;

  /// Calculate the for a tansaction with this structure.
  ///
  /// The fee rate, inputs, and payments, will all be for the same coin. The returned fee is
  /// denominated in this coin.
  fn calculate_fee(
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<S>>,
    payments: Vec<Payment<AddressFor<S>>>,
    change: Option<KeyFor<S>>,
  ) -> Amount;

  /// Plan a transaction.
  ///
  /// This must only require the same fee as would be returned by `calculate_fee`. The caller is
  /// trusted to maintain `sum(inputs) - sum(payments) >= if change.is_some() { DUST } else { 0 }`.
  ///
  /// `change` will always be an address belonging to the Serai network. If it is `Some`, a change
  /// output must be created.
  fn plan(
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<S>>,
    payments: Vec<Payment<AddressFor<S>>>,
    change: Option<KeyFor<S>>,
  ) -> PlannedTransaction<S, Self::SignableTransaction, A>;

  /// Obtain a PlannedTransaction via amortizing the fee over the payments.
  ///
  /// `operating_costs` is accrued to if Serai faces the burden of a fee or drops inputs not worth
  /// accumulating. `operating_costs` will be amortized along with this transaction's fee as
  /// possible, if there is a change output. Please see `spec/processor/UTXO Management.md` for
  /// more information.
  ///
  /// Returns `None` if the fee exceeded the inputs, or `Some` otherwise.
  // TODO: Enum for Change of None, Some, Mandatory
  fn plan_transaction_with_fee_amortization(
    operating_costs: &mut u64,
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<S>>,
    mut payments: Vec<Payment<AddressFor<S>>>,
    mut change: Option<KeyFor<S>>,
  ) -> Option<AmortizePlannedTransaction<S, Self::SignableTransaction, A>> {
    // If there's no change output, we can't recoup any operating costs we would amortize
    // We also don't have any losses if the inputs are written off/the change output is reduced
    let mut operating_costs_if_no_change = 0;
    let operating_costs_in_effect =
      if change.is_none() { &mut operating_costs_if_no_change } else { operating_costs };

    // Sanity checks
    {
      assert!(!inputs.is_empty());
      assert!((!payments.is_empty()) || change.is_some());
      let coin = inputs.first().unwrap().balance().coin;
      for input in &inputs {
        assert_eq!(coin, input.balance().coin);
      }
      for payment in &payments {
        assert_eq!(coin, payment.balance().coin);
      }
      assert!(
        (inputs.iter().map(|input| input.balance().amount.0).sum::<u64>() +
          *operating_costs_in_effect) >=
          payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>(),
        "attempted to fulfill payments without a sufficient input set"
      );
    }

    let coin = inputs.first().unwrap().balance().coin;

    // Amortization
    {
      // Sort payments from high amount to low amount
      payments.sort_by(|a, b| a.balance().amount.0.cmp(&b.balance().amount.0).reverse());

      let mut fee = Self::calculate_fee(fee_rate, inputs.clone(), payments.clone(), change).0;
      let mut amortized = 0;
      while !payments.is_empty() {
        // We need to pay the fee, and any accrued operating costs, minus what we've already
        // amortized
        let adjusted_fee = (*operating_costs_in_effect + fee).saturating_sub(amortized);

        /*
          Ideally, we wouldn't use a ceil div yet would be accurate about it. Any remainder could
          be amortized over the largest outputs, which wouldn't be relevant here as we only work
          with the smallest output. The issue is the theoretical edge case where all outputs have
          the same value and are of the minimum value. In that case, none would be able to have the
          remainder amortized as it'd cause them to need to be dropped. Using a ceil div avoids
          this.
        */
        let per_payment_fee = adjusted_fee.div_ceil(u64::try_from(payments.len()).unwrap());
        // Pop the last payment if it can't pay the fee, remaining about the dust limit as it does
        if payments.last().unwrap().balance().amount.0 <= (per_payment_fee + S::dust(coin).0) {
          amortized += payments.pop().unwrap().balance().amount.0;
          // Recalculate the fee and try again
          fee = Self::calculate_fee(fee_rate, inputs.clone(), payments.clone(), change).0;
          continue;
        }
        // Break since all of these payments shouldn't be dropped
        break;
      }

      // If we couldn't amortize the fee over the payments, check if we even have enough to pay it
      if payments.is_empty() {
        // If we don't have a change output, we simply return here
        // We no longer have anything to do here, nor any expectations
        if change.is_none() {
          None?;
        }

        let inputs = inputs.iter().map(|input| input.balance().amount.0).sum::<u64>();
        // Checks not just if we can pay for it, yet that the would-be change output is at least
        // dust
        if inputs < (fee + S::dust(coin).0) {
          // Write off these inputs
          *operating_costs_in_effect += inputs;
          // Yet also claw back the payments we dropped, as we only lost the change
          // The dropped payments will be worth less than the inputs + operating_costs we started
          // with, so this shouldn't use `saturating_sub`
          *operating_costs_in_effect -= amortized;
          None?;
        }
      } else {
        // Since we have payments which can pay the fee we ended up with, amortize it
        let adjusted_fee = (*operating_costs_in_effect + fee).saturating_sub(amortized);
        let per_payment_base_fee = adjusted_fee / u64::try_from(payments.len()).unwrap();
        let payments_paying_one_atomic_unit_more =
          usize::try_from(adjusted_fee % u64::try_from(payments.len()).unwrap()).unwrap();

        for (i, payment) in payments.iter_mut().enumerate() {
          let per_payment_fee =
            per_payment_base_fee + u64::from(u8::from(i < payments_paying_one_atomic_unit_more));
          payment.balance().amount.0 -= per_payment_fee;
          amortized += per_payment_fee;
        }
        assert!(amortized >= (*operating_costs_in_effect + fee));

        // If the change is less than the dust, drop it
        let would_be_change = inputs.iter().map(|input| input.balance().amount.0).sum::<u64>() -
          payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>() -
          fee;
        if would_be_change < S::dust(coin).0 {
          change = None;
          *operating_costs_in_effect += would_be_change;
        }
      }

      // Update the amount of operating costs
      *operating_costs_in_effect = (*operating_costs_in_effect + fee).saturating_sub(amortized);
    }

    // Because we amortized, or accrued as operating costs, the fee, make the transaction
    let effected_payments = payments.iter().map(|payment| payment.balance().amount).collect();
    let has_change = change.is_some();
    let PlannedTransaction { signable, eventuality, auxilliary } =
      Self::plan(fee_rate, inputs, payments, change);
    Some(AmortizePlannedTransaction {
      effected_payments,
      has_change,
      signable,
      eventuality,
      auxilliary,
    })
  }

  /// Create a tree to fulfill a set of payments.
  ///
  /// Returns a `TreeTransaction` whose children (and arbitrary children of children) fulfill all
  /// these payments. This tree root will be able to be made with a change output.
  fn tree(payments: &[Payment<AddressFor<S>>]) -> TreeTransaction<AddressFor<S>> {
    // This variable is for the current layer of the tree being built
    let mut tree = Vec::with_capacity(payments.len().div_ceil(Self::MAX_OUTPUTS));

    // Push the branches for the leaves (the payments out)
    for payments in payments.chunks(Self::MAX_OUTPUTS) {
      let value = payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>();
      tree.push(TreeTransaction::<AddressFor<S>>::Leaves { payments: payments.to_vec(), value });
    }

    // While we haven't calculated a tree root, or the tree root doesn't support a change output,
    // keep working
    while (tree.len() != 1) || (tree[0].children() == Self::MAX_OUTPUTS) {
      let mut branch_layer = vec![];
      for children in tree.chunks(Self::MAX_OUTPUTS) {
        branch_layer.push(TreeTransaction::<AddressFor<S>>::Branch {
          children: children.to_vec(),
          value: children.iter().map(TreeTransaction::value).sum(),
        });
      }
      tree = branch_layer;
    }
    assert_eq!(tree.len(), 1);
    let tree_root = tree.remove(0);
    assert!((tree_root.children() + 1) <= Self::MAX_OUTPUTS);
    tree_root
  }
}
