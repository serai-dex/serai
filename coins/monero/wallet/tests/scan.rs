use monero_serai::transaction::Transaction;
use monero_wallet::{rpc::Rpc, address::SubaddressIndex, extra::PaymentId, GuaranteedScanner};

mod runner;

test!(
  scan_standard_address,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::new(view.clone());
      builder.add_payment(view.legacy_address(Network::Mainnet), 5);
      (builder.build().unwrap(), scanner)
    },
    |rpc, block, tx: Transaction, _, mut state: Scanner| async move {
      let output = state.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      let dummy_payment_id = PaymentId::Encrypted([0u8; 8]);
      assert_eq!(output.payment_id(), Some(dummy_payment_id));
    },
  ),
);

test!(
  scan_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 1).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.subaddress(Network::Mainnet, subaddress), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |rpc, block, tx: Transaction, _, mut state: (Scanner, SubaddressIndex)| async move {
      let output =
        state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), Some(state.1));
    },
  ),
);

test!(
  scan_integrated_address,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::new(view.clone());

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.legacy_integrated_address(Network::Mainnet, payment_id), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    |rpc, block, tx: Transaction, _, mut state: (Scanner, [u8; 8])| async move {
      let output =
        state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
    },
  ),
);

test!(
  scan_guaranteed,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 2).unwrap();

      let view = runner::random_guaranteed_address().1;
      let mut scanner = GuaranteedScanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.address(Network::Mainnet, None, None), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |rpc, block, tx: Transaction, _, mut state: (GuaranteedScanner, SubaddressIndex)| async move {
      let output =
        state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), Some(state.1));
    },
  ),
);

test!(
  scan_guaranteed_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 2).unwrap();

      let view = runner::random_guaranteed_address().1;
      let mut scanner = GuaranteedScanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.address(Network::Mainnet, Some(subaddress), None), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |rpc, block, tx: Transaction, _, mut state: (GuaranteedScanner, SubaddressIndex)| async move {
      let output =
        state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.subaddress(), Some(state.1));
    },
  ),
);

test!(
  scan_guaranteed_integrated,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_guaranteed_address().1;
      let scanner = GuaranteedScanner::new(view.clone());
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.address(Network::Mainnet, None, Some(payment_id)), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    |rpc, block, tx: Transaction, _, mut state: (GuaranteedScanner, [u8; 8])| async move {
      let output =
        state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
    },
  ),
);

#[rustfmt::skip]
test!(
  scan_guaranteed_integrated_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 3).unwrap();

      let view = runner::random_guaranteed_address().1;
      let mut scanner = GuaranteedScanner::new(view.clone());
      scanner.register_subaddress(subaddress);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.address(Network::Mainnet, Some(subaddress), Some(payment_id)), 5);
      (builder.build().unwrap(), (scanner, payment_id, subaddress))
    },
    |
      rpc,
      block,
      tx: Transaction,
      _,
      mut state: (GuaranteedScanner, [u8; 8], SubaddressIndex),
    | async move {
      let output = state.0.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.payment_id(), Some(PaymentId::Encrypted(state.1)));
      assert_eq!(output.subaddress(), Some(state.2));
    },
  ),
);
