use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{Coin, Amount, Balance};

use primitives::{Address, Payment};
use scanner::ScannerFeed;

/// A transaction within a tree to fulfill payments.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum TreeTransaction<A: Address> {
  /// A transaction for the leaves (payments) of the tree.
  Leaves {
    /// The payments within this transaction.
    payments: Vec<Payment<A>>,
    /// The sum value of the payments.
    value: u64,
  },
  /// A transaction for the branches of the tree.
  Branch {
    /// The child transactions.
    children: Vec<Self>,
    /// The sum value of the child transactions.
    value: u64,
  },
}
impl<A: Address> TreeTransaction<A> {
  /// How many children this transaction has.
  ///
  /// A child is defined as any dependent, whether payment or transaction.
  pub fn children(&self) -> usize {
    match self {
      Self::Leaves { payments, .. } => payments.len(),
      Self::Branch { children, .. } => children.len(),
    }
  }

  /// The value this transaction wants to spend.
  pub fn value(&self) -> u64 {
    match self {
      Self::Leaves { value, .. } | Self::Branch { value, .. } => *value,
    }
  }

  /// The payments to make to enable this transaction's children.
  ///
  /// A child is defined as any dependent, whether payment or transaction.
  ///
  /// The input value given to this transaction MUST be less than or equal to the desired value.
  /// The difference will be amortized over all dependents.
  ///
  /// Returns None if no payments should be made. Returns Some containing a non-empty Vec if any
  /// payments should be made.
  pub fn payments<S: ScannerFeed>(
    &self,
    coin: Coin,
    branch_address: &A,
    input_value: u64,
  ) -> Option<Vec<Payment<A>>> {
    // Fetch the amounts for the payments we'll make
    let mut amounts: Vec<_> = match self {
      Self::Leaves { payments, .. } => payments
        .iter()
        .map(|payment| {
          assert_eq!(payment.balance().coin, coin);
          Some(payment.balance().amount.0)
        })
        .collect(),
      Self::Branch { children, .. } => children.iter().map(|child| Some(child.value())).collect(),
    };

    // We need to reduce them so their sum is our input value
    assert!(input_value <= self.value());
    let amount_to_amortize = self.value() - input_value;

    // If any payments won't survive the reduction, set them to None
    let mut amortized = 0;
    'outer: while amounts.iter().any(Option::is_some) && (amortized < amount_to_amortize) {
      let adjusted_fee = amount_to_amortize - amortized;
      let amounts_len =
        u64::try_from(amounts.iter().filter(|amount| amount.is_some()).count()).unwrap();
      let per_payment_fee_check = adjusted_fee.div_ceil(amounts_len);

      // Check each amount to see if it's not viable
      let mut i = 0;
      while i < amounts.len() {
        if let Some(amount) = amounts[i] {
          if amount.saturating_sub(per_payment_fee_check) < S::dust(coin).0 {
            amounts[i] = None;
            amortized += amount;
            // If this amount wasn't viable, re-run with the new fee/amortization amounts
            continue 'outer;
          }
        }
        i += 1;
      }

      // Now that we have the payments which will survive, reduce them
      for (i, amount) in amounts.iter_mut().enumerate() {
        if let Some(amount) = amount {
          *amount -= adjusted_fee / amounts_len;
          if i < usize::try_from(adjusted_fee % amounts_len).unwrap() {
            *amount -= 1;
          }
        }
      }
      break;
    }

    // Now that we have the reduced amounts, create the payments
    let payments: Vec<_> = match self {
      Self::Leaves { payments, .. } => {
        payments
          .iter()
          .zip(amounts)
          .filter_map(|(payment, amount)| {
            amount.map(|amount| {
              // The existing payment, with the new amount
              Payment::new(
                payment.address().clone(),
                Balance { coin, amount: Amount(amount) },
                payment.data().clone(),
              )
            })
          })
          .collect()
      }
      Self::Branch { .. } => {
        amounts
          .into_iter()
          .filter_map(|amount| {
            amount.map(|amount| {
              // A branch output with the new amount
              Payment::new(branch_address.clone(), Balance { coin, amount: Amount(amount) }, None)
            })
          })
          .collect()
      }
    };

    // Use None for vec![] so we never actually use vec![]
    if payments.is_empty() {
      None?;
    }
    Some(payments)
  }
}
