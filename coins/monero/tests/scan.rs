use rand::RngCore;

use monero_serai::{transaction::Transaction, wallet::address::SubaddressIndex};

mod runner;

test!(
  scan_standard_address,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      builder.add_payment(view.address(Network::Mainnet, AddressSpec::Standard), 5);
      (builder.build().unwrap(), scanner)
    },
    |_, tx: Transaction, _, mut state: Scanner| async move {
      let output = state.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 1).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      scanner.register_subaddress(subaddress);

      builder.add_payment(view.address(Network::Mainnet, AddressSpec::Subaddress(subaddress)), 5);
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |_, tx: Transaction, _, mut state: (Scanner, SubaddressIndex)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, Some(state.1));
    },
  ),
);

test!(
  scan_integrated_address,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(view.address(Network::Mainnet, AddressSpec::Integrated(payment_id)), 5);
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
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured { subaddress: None, payment_id: None, guaranteed: false },
        ),
        5,
      );
      (builder.build().unwrap(), scanner)
    },
    |_, tx: Transaction, _, mut state: Scanner| async move {
      let output = state.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_featured_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(0, 2).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      scanner.register_subaddress(subaddress);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: Some(subaddress),
            payment_id: None,
            guaranteed: false,
          },
        ),
        5,
      );
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |_, tx: Transaction, _, mut state: (Scanner, SubaddressIndex)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, Some(state.1));
    },
  ),
);

test!(
  scan_featured_integrated,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: None,
            payment_id: Some(payment_id),
            guaranteed: false,
          },
        ),
        5,
      );
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
      let subaddress = SubaddressIndex::new(0, 3).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));
      scanner.register_subaddress(subaddress);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: Some(subaddress),
            payment_id: Some(payment_id),
            guaranteed: false,
          },
        ),
        5,
      );
      (builder.build().unwrap(), (scanner, payment_id, subaddress))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8], SubaddressIndex)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
      assert_eq!(output.metadata.subaddress, Some(state.2));
    },
  ),
);

test!(
  scan_guaranteed_standard,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), None);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured { subaddress: None, payment_id: None, guaranteed: true },
        ),
        5,
      );
      (builder.build().unwrap(), scanner)
    },
    |_, tx: Transaction, _, mut state: Scanner| async move {
      let output = state.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  scan_guaranteed_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      let subaddress = SubaddressIndex::new(1, 0).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), None);
      scanner.register_subaddress(subaddress);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: Some(subaddress),
            payment_id: None,
            guaranteed: true,
          },
        ),
        5,
      );
      (builder.build().unwrap(), (scanner, subaddress))
    },
    |_, tx: Transaction, _, mut state: (Scanner, SubaddressIndex)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.subaddress, Some(state.1));
    },
  ),
);

test!(
  scan_guaranteed_integrated,
  (
    |_, mut builder: Builder, _| async move {
      let view = runner::random_address().1;
      let scanner = Scanner::from_view(view.clone(), None);
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: None,
            payment_id: Some(payment_id),
            guaranteed: true,
          },
        ),
        5,
      );
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
      let subaddress = SubaddressIndex::new(1, 1).unwrap();

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), None);
      scanner.register_subaddress(subaddress);

      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);

      builder.add_payment(
        view.address(
          Network::Mainnet,
          AddressSpec::Featured {
            subaddress: Some(subaddress),
            payment_id: Some(payment_id),
            guaranteed: true,
          },
        ),
        5,
      );
      (builder.build().unwrap(), (scanner, payment_id, subaddress))
    },
    |_, tx: Transaction, _, mut state: (Scanner, [u8; 8], SubaddressIndex)| async move {
      let output = state.0.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.metadata.payment_id, state.1);
      assert_eq!(output.metadata.subaddress, Some(state.2));
    },
  ),
);
