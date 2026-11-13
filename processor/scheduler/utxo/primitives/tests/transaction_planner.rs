mod planner_tree {
  use scheduler_test_primitives::*;
  use serai_primitives::coin::ExternalCoin;
  use serai_processor_utxo_scheduler_primitives::{TransactionPlanner as _, TreeTransaction};

  // The amounts of every payment in the tree, left to right
  fn get_leaf_amounts(tx: &TreeTransaction<TestAddress>) -> Vec<u64> {
    match tx {
      TreeTransaction::Leaves { payments, .. } => {
        payments.iter().map(|payment| payment.balance().amount.0).collect()
      }
      TreeTransaction::Branch { children, .. } => {
        children.iter().flat_map(get_leaf_amounts).collect()
      }
    }
  }

  // The tree's shape, eg `B[L3,L1]` for a branch of two leaves with 3 and 1 payments
  fn tree_shape_to_string(tx: &TreeTransaction<TestAddress>) -> String {
    match tx {
      TreeTransaction::Leaves { payments, .. } => format!("L{}", payments.len()),
      TreeTransaction::Branch { children, .. } => {
        format!("B[{}]", children.iter().map(tree_shape_to_string).collect::<Vec<_>>().join(","))
      }
    }
  }

  // Assert every node's value is the sum of the payments under it
  fn assert_node_values(tx: &TreeTransaction<TestAddress>) {
    assert_eq!(tx.value(), get_leaf_amounts(tx).iter().sum::<u64>());
    if let TreeTransaction::Branch { children, .. } = tx {
      children.iter().for_each(assert_node_values);
    }
  }

  #[test]
  fn single_payment_is_a_leaves_root() {
    let payments = payments(1);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "L1");
    assert_eq!(get_leaf_amounts(&tree), [100]);
    assert_eq!(tree.value(), 100);
  }

  #[test]
  fn almost_full_single_leaves_dont_wrap_into_a_branch() {
    let payments = payments(2);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "L2");
    assert_eq!(get_leaf_amounts(&tree), [100, 200]);
    assert_eq!(tree.value(), 300);
  }

  #[test]
  fn full_single_leaves_wrap_into_a_branch() {
    let payments = payments(3);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "B[L3]");
    assert_eq!(get_leaf_amounts(&tree), [100, 200, 300]);
    assert_eq!(tree.value(), 600);
  }

  #[test]
  fn almost_full_single_branch_doesnt_wrap_into_another_branch() {
    let payments = payments(6);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "B[L3,L3]");
    assert_eq!(get_leaf_amounts(&tree), [100, 200, 300, 400, 500, 600]);
    assert_eq!(tree.value(), 2100);
  }

  #[test]
  fn full_single_branch_wraps_into_another_branch() {
    let payments = payments(7);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "B[B[L3,L3,L1]]");
    assert_eq!(get_leaf_amounts(&tree), [100, 200, 300, 400, 500, 600, 700]);
    assert_eq!(tree.value(), 2800);
  }

  #[test]
  fn overflowing_leaves_split_into_two_branches() {
    let payments = payments(10);
    let tree = TestPlanner::tree(&payments);
    assert_eq!(tree_shape_to_string(&tree), "B[B[L3,L3,L3],B[L1]]");
    assert_eq!(get_leaf_amounts(&tree), [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]);
    assert_eq!(tree.value(), 5500);
  }

  #[test]
  fn node_value_matches_amount_sum() {
    let payments = payments(10);
    let tree = TestPlanner::tree(&payments);
    assert_node_values(&tree);
  }

  #[test]
  fn leaves_root_at_full_value_keeps_its_payments() {
    let payments = payments(2);
    let tree = TestPlanner::tree(&payments);
    let root_payments = tree
      .payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), tree.value())
      .expect("payments were dropped despite a full-value input");

    let (addresses, amounts) = get_addresses_and_amounts(&root_payments);
    assert_eq!(addresses, vec![TestAddress(0), TestAddress(1)]);
    assert_eq!(amounts, vec![100, 200]);
  }

  #[test]
  fn branch_root_at_full_value_pays_its_children_to_the_branch_address() {
    let payments = payments(7);
    let tree = TestPlanner::tree(&payments);
    let root_payments = tree
      .payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), tree.value())
      .expect("payments were dropped despite a full-value input");

    let (addresses, amounts) = get_addresses_and_amounts(&root_payments);
    assert_eq!(addresses, vec![TestAddress(111)]);
    assert_eq!(amounts, vec![2800]);
  }
}

mod planner_plan_tx_with_fee_amortization {
  use ciphersuite::WrappedGroup as _;
  use dalek_ff_group::Ed25519;

  use scheduler_test_primitives::*;
  use primitives::Payment;
  use serai_primitives::balance::Amount;
  use serai_processor_utxo_scheduler_primitives::AmortizePlannedTransaction;
  use serai_processor_utxo_scheduler_primitives::TransactionPlanner as _;

  async fn plan(
    operating_costs: &mut u64,
    input: u64,
    payments: Vec<Payment<TestAddress>>,
    change: bool,
  ) -> Option<AmortizePlannedTransaction<TestFeed, TestSignableTransaction, ()>> {
    TestPlanner
      .plan_transaction_with_fee_amortization(
        operating_costs,
        &TestBlock,
        vec![TestOutput(input)],
        payments,
        change.then(Ed25519::generator),
      )
      .await
      .unwrap()
  }

  #[tokio::test]
  async fn fee_is_amortized() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 200), payment(1, 100), payment(2, 50)];
    let tx = plan(&mut operating_costs, 1000, payments, true).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(190), Amount(90), Amount(40)]);
    assert!(tx.has_change);
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn smallest_payment_dropped_at_exact_dust() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 200), payment(1, 20), payment(2, 100)];
    let tx = plan(&mut operating_costs, 1000, payments, true).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(197), Amount(98)]);
    assert!(tx.has_change);
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn payment_not_dropped_right_above_dust() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 200), payment(1, 100), payment(2, 21)];
    let tx = plan(&mut operating_costs, 1000, payments, true).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(190), Amount(90), Amount(11)]);
    assert!(tx.has_change);
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn all_payments_dropped_without_change_plans_nothing() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 13), payment(1, 11)];
    let tx = plan(&mut operating_costs, 100, payments, false).await;

    assert!(tx.is_none());
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn operating_costs_get_paid() {
    let mut operating_costs = 30;
    let payments = vec![payment(0, 200), payment(1, 50), payment(2, 100)];
    let tx = plan(&mut operating_costs, 1000, payments, true).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(180), Amount(80), Amount(30)]);
    assert!(tx.has_change);
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn operating_costs_not_paid_if_no_change() {
    let mut operating_costs = 30;
    let payments = vec![payment(0, 200), payment(1, 50), payment(2, 100)];
    let tx = plan(&mut operating_costs, 350, payments, false).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(191), Amount(92), Amount(42)]);
    assert!(!tx.has_change);
    assert_eq!(operating_costs, 30);
  }

  #[tokio::test]
  async fn dust_change_becomes_operating_cost() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 200), payment(1, 50), payment(2, 100)];
    let tx = plan(&mut operating_costs, 355, payments, true).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(190), Amount(90), Amount(40)]);
    assert!(!tx.has_change);
    assert_eq!(operating_costs, 5);
  }

  #[tokio::test]
  async fn excess_input_does_not_redistribute_if_no_change() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 200), payment(1, 50), payment(2, 100)];
    let tx = plan(&mut operating_costs, 1000, payments, false).await.expect("Nothing was planned");

    assert_eq!(tx.effected_payments, vec![Amount(191), Amount(92), Amount(42)]);
    assert!(!tx.has_change);
    assert_eq!(operating_costs, 0);
  }

  #[tokio::test]
  async fn all_payments_dropped_if_below_operating_costs() {
    let mut operating_costs = 1000;
    let payments = vec![payment(0, 200), payment(1, 50), payment(2, 100)];
    let tx = plan(&mut operating_costs, 1000, payments, true).await.expect("Nothing was planned");

    assert!(tx.effected_payments.is_empty());
    assert!(tx.has_change);
    assert_eq!(operating_costs, 665);
  }

  #[tokio::test]
  async fn change_only_tx_not_worth_making_plans_nothing() {
    let mut operating_costs = 0;
    let payments = vec![payment(0, 12)];
    let tx = plan(&mut operating_costs, 20, payments, true).await;

    assert!(tx.is_none());
    assert_eq!(operating_costs, 8);
  }
}
