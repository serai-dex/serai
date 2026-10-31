use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  coin::ExternalCoin,
  balance::{Amount, ExternalBalance},
};

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
    coin: ExternalCoin,
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
        if let Some(amount) = amounts[i] &&
          (amount.checked_sub(per_payment_fee_check) < Some(S::dust(coin).0))
        {
          amounts[i] = None;
          amortized += amount;
          // If this amount wasn't viable, re-run with the new fee/amortization amounts
          continue 'outer;
        }
        i += 1;
      }

      // Now that we have the payments which will survive, reduce them
      for (i, amount) in amounts.iter_mut().filter_map(Option::as_mut).enumerate() {
        *amount -= adjusted_fee / amounts_len;
        if i < usize::try_from(adjusted_fee % amounts_len).unwrap() {
          *amount -= 1;
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
                ExternalBalance { coin, amount: Amount(amount) },
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
              Payment::new(branch_address.clone(), ExternalBalance { coin, amount: Amount(amount) })
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tests::FakeAddress;
  use crate::tests::FakeFeed;

  fn payment(address: u32, amount: u64) -> Payment<FakeAddress> {
    Payment::new(
      FakeAddress(address),
      ExternalBalance { amount: Amount(amount), coin: ExternalCoin::Monero },
    )
  }

  fn get_addresses_and_amounts(payments: &[Payment<FakeAddress>]) -> (Vec<FakeAddress>, Vec<u64>) {
    let addresses = payments.iter().map(|p| p.address().clone()).collect();
    let amounts = payments.iter().map(|p| p.balance().amount.0).collect();

    (addresses, amounts)
  }

  fn fake_addresses(qty: u32) -> Vec<FakeAddress> {
    let mut fake_addresses: Vec<FakeAddress> = Vec::with_capacity(qty.try_into().unwrap());

    for i in 0 .. qty {
      fake_addresses.push(FakeAddress(i));
    }

    fake_addresses
  }

  #[test]
  #[should_panic(expected = "assertion failed: input_value <= self.value()")]
  fn input_gt_value_panics() {
    let input_value = 101;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 90), payment(1, 10)], value: 100 };
    let _ = leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value);
  }

  #[test]
  #[should_panic(expected = "assertion `left == right` failed\n  left: Monero\n right: Bitcoin")]
  fn payments_in_wrong_coin_panics() {
    let input_value = 100;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 90), payment(1, 10)], value: 100 };
    let _ = leaves.payments::<FakeFeed>(ExternalCoin::Bitcoin, &FakeAddress(111), input_value);
  }

  #[test]
  fn fee_splits_evenly() {
    let input_value = 570;
    let leaves = TreeTransaction::Leaves {
      payments: vec![payment(0, 100), payment(1, 200), payment(2, 300)],
      value: 600,
    };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses, amounts) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts, vec![90, 190, 290]);
    assert_eq!(addresses, fake_addresses(3));
  }

  #[test]
  fn remainder_comes_off_first_payment() {
    let input_value = 569;
    let leaves = TreeTransaction::Leaves {
      payments: vec![payment(0, 100), payment(1, 200), payment(2, 300)],
      value: 600,
    };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses, amounts) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts, vec![89, 190, 290]);
    assert_eq!(addresses, fake_addresses(3));
  }

  #[test]
  fn payment_kept_at_exactly_dust() {
    let input_value = 200;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 20), payment(1, 200)], value: 220 };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![10, 190]);
    assert_eq!(addresses_result, fake_addresses(2));
  }

  #[test]
  fn payment_dropped_just_below_dust() {
    let input_value = 199;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 20), payment(1, 200)], value: 220 };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![199]);
    assert_eq!(addresses_result, vec![FakeAddress(1)]);
  }

  #[test]
  fn payment_dropped_then_restart() {
    let input_value = 485;
    let payments = vec![payment(0, 15), payment(1, 200), payment(2, 300)];
    let leaves = TreeTransaction::Leaves { payments, value: 515 };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![192, 293]);
    assert_eq!(addresses_result, vec![FakeAddress(1), FakeAddress(2)]);
  }

  #[test]
  fn all_payments_dropped_for_becoming_dust() {
    let input_value = 4;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 12), payment(1, 12)], value: 24 };
    let payments_result =
      leaves.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value);

    assert!(payments_result.is_none());
  }

  #[test]
  fn branch_outputs_go_to_the_branch_address() {
    let input_value = 890;
    let leaves1 =
      TreeTransaction::Leaves { payments: vec![payment(0, 200), payment(1, 100)], value: 300 };
    let leaves2 = TreeTransaction::Leaves { payments: vec![payment(2, 600)], value: 600 };
    let branch = TreeTransaction::Branch { children: vec![leaves1, leaves2], value: 900 };
    let payments_result =
      branch.payments::<FakeFeed>(ExternalCoin::Monero, &FakeAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![295, 595]);
    assert_eq!(addresses_result, vec![FakeAddress(111), FakeAddress(111)]);
  }
}
