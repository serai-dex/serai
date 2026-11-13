mod tree_transaction {
  use scheduler_test_primitives::*;
  use serai_primitives::coin::ExternalCoin;
  use serai_processor_utxo_scheduler_primitives::TreeTransaction;

  fn test_addresses(qty: u32) -> Vec<TestAddress> {
    let mut test_addresses: Vec<TestAddress> = Vec::with_capacity(qty.try_into().unwrap());

    for i in 0 .. qty {
      test_addresses.push(TestAddress(i));
    }

    test_addresses
  }

  #[test]
  #[should_panic(expected = "assertion failed: input_value <= self.value()")]
  fn input_gt_value_panics() {
    let input_value = 101;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 90), payment(1, 10)], value: 100 };
    let _ = leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value);
  }

  #[test]
  #[should_panic(expected = "assertion `left == right` failed\n  left: Monero\n right: Bitcoin")]
  fn payments_in_wrong_coin_panics() {
    let input_value = 100;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 90), payment(1, 10)], value: 100 };
    let _ = leaves.payments::<TestFeed>(ExternalCoin::Bitcoin, &TestAddress(111), input_value);
  }

  #[test]
  fn fee_splits_evenly() {
    let input_value = 570;
    let leaves = TreeTransaction::Leaves {
      payments: vec![payment(0, 100), payment(1, 200), payment(2, 300)],
      value: 600,
    };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses, amounts) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts, vec![90, 190, 290]);
    assert_eq!(addresses, test_addresses(3));
  }

  #[test]
  fn remainder_comes_off_first_payment() {
    let input_value = 569;
    let leaves = TreeTransaction::Leaves {
      payments: vec![payment(0, 100), payment(1, 200), payment(2, 300)],
      value: 600,
    };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses, amounts) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts, vec![89, 190, 290]);
    assert_eq!(addresses, test_addresses(3));
  }

  #[test]
  fn payment_kept_at_exactly_dust() {
    let input_value = 200;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 20), payment(1, 200)], value: 220 };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![10, 190]);
    assert_eq!(addresses_result, test_addresses(2));
  }

  #[test]
  fn payment_dropped_just_below_dust() {
    let input_value = 199;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 20), payment(1, 200)], value: 220 };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![199]);
    assert_eq!(addresses_result, vec![TestAddress(1)]);
  }

  #[test]
  fn payment_dropped_then_restart() {
    let input_value = 485;
    let payments = vec![payment(0, 15), payment(1, 200), payment(2, 300)];
    let leaves = TreeTransaction::Leaves { payments, value: 515 };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![192, 293]);
    assert_eq!(addresses_result, vec![TestAddress(1), TestAddress(2)]);
  }

  #[test]
  fn all_payments_dropped_for_becoming_dust() {
    let input_value = 4;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 12), payment(1, 12)], value: 24 };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value);

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
      branch.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![295, 595]);
    assert_eq!(addresses_result, vec![TestAddress(111), TestAddress(111)]);
  }

  #[test]
  fn dropped_payment_exceeding_shortfall_leaves_remainder() {
    let input_value = 1002;
    let leaves =
      TreeTransaction::Leaves { payments: vec![payment(0, 12), payment(1, 1000)], value: 1012 };
    let payments_result =
      leaves.payments::<TestFeed>(ExternalCoin::Monero, &TestAddress(111), input_value).unwrap();
    let (addresses_result, amounts_result) = get_addresses_and_amounts(&payments_result);

    assert_eq!(amounts_result, vec![1000]); // Leaves a remainder of 2
    assert_eq!(addresses_result, vec![TestAddress(1)]);
  }
}
