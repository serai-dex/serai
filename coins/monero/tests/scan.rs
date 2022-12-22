use rand::RngCore;

use monero_serai::{transaction::Transaction};

mod runner;

test!(
  scan_standard_address,
  (
    |_, mut builder: Builder, _| async move {
      let scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      builder.add_payment(scanner.address(), 5);
      (builder.build().unwrap(), (scanner,))
    },
    |_, tx: Transaction, _, mut state: (Scanner,)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      let subaddress_index = (0, 1);
      builder.add_payment(scanner.subaddress(subaddress_index), 5);
      (builder.build().unwrap(), (scanner, subaddress_index))
    },
    |_, tx: Transaction, _, mut state: (Scanner, (u32, u32))| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, state.1);
    },
  ),
);

test!(
  scan_integrated_address,
  (
    |_, mut builder: Builder, _| async move {
      let scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(scanner.integrated_address(payment_id), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8])| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
    },
  ),
);

test!(
  scan_featured_standard,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      builder.add_payment(scanner.featured_address(None, None, false), 5);
      (builder.build().unwrap(), (scanner,))
    },
    |_, tx: Transaction, _, mut state: (Scanner,)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_featured_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      let subaddress_index = (0, 2);
      builder.add_payment(scanner.featured_address(Some(subaddress_index), None, false), 5);
      (builder.build().unwrap(), (scanner, subaddress_index))
    },
    |_, tx: Transaction, _, mut state: (Scanner, (u32, u32))| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, state.1);
    },
  ),
);

test!(
  scan_featured_integrated,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(scanner.featured_address(None, Some(payment_id), false), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8])| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
    },
  ),
);

test!(
  scan_featured_integrated_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner =
        Scanner::from_view(runner::random_address().1, Network::Mainnet, Some(HashSet::new()));
      let subaddress_index = (0, 3);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder
        .add_payment(scanner.featured_address(Some(subaddress_index), Some(payment_id), false), 5);
      (builder.build().unwrap(), (scanner, payment_id, subaddress_index))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8], (u32, u32))| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
      assert_eq!(output.metadata.subaddress, state.2);
    },
  ),
);

test!(
  scan_guaranteed_standard,
  (
    |_, mut builder: Builder, _| async move {
      let scanner = Scanner::from_view(runner::random_address().1, Network::Mainnet, None);

      builder.add_payment(scanner.address(), 5);
      (builder.build().unwrap(), (scanner,))
    },
    |_, tx: Transaction, _, mut state: (Scanner,)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_guaranteed_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner = Scanner::from_view(runner::random_address().1, Network::Mainnet, None);
      let subaddress_index = (0, 1);

      builder.add_payment(scanner.subaddress(subaddress_index), 5);
      (builder.build().unwrap(), (scanner, subaddress_index))
    },
    |_, tx: Transaction, _, mut state: (Scanner, (u32, u32))| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, state.1);
    },
  ),
);

test!(
  scan_guaranteed_integrated,
  (
    |_, mut builder: Builder, _| async move {
      let scanner = Scanner::from_view(runner::random_address().1, Network::Mainnet, None);
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(scanner.integrated_address(payment_id), 5);
      (builder.build().unwrap(), (scanner, payment_id))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8])| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
    },
  ),
);

test!(
  scan_guaranteed_integrated_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let mut scanner = Scanner::from_view(runner::random_address().1, Network::Mainnet, None);
      let subaddress_index = (0, 2);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder
        .add_payment(scanner.featured_address(Some(subaddress_index), Some(payment_id), true), 5);
      (builder.build().unwrap(), (scanner, payment_id, subaddress_index))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8], (u32, u32))| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
      assert_eq!(output.metadata.subaddress, state.2);
    },
  ),
);
