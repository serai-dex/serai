use monero_serai::{
  transaction::Transaction,
  wallet::{extra::Extra, address::SubaddressIndex, ReceivedOutput, SpendableOutput},
  rpc::Rpc,
};

mod runner;

test!(
  spend_miner_output,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 5);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, _| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
    },
  ),
);

test!(
  spend_multiple_outputs,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 1000000000000);
      builder.add_payment(addr, 2000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, _| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      assert_eq!(outputs[1].commitment().amount, 2000000000000);
      outputs
    },
  ),
  (
    |rpc, mut builder: Builder, addr, mut outputs: Vec<ReceivedOutput>| async move {
      for output in outputs.drain(..) {
        builder.add_input(SpendableOutput::from(&rpc, output).await.unwrap());
      }
      builder.add_payment(addr, 6);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, _| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 6);
    },
  ),
);

test!(
  // Ideally, this would be single_R, yet it isn't feasible to apply allow(non_snake_case) here
  single_r_subaddress_send,
  (
    // Consume this builder for an output we can use in the future
    // This is needed because we can't get the input from the passed in builder
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 1000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, _| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      outputs
    },
  ),
  (
    |rpc: Rpc<_>, _, _, mut outputs: Vec<ReceivedOutput>| async move {
      let change_view = ViewPair::new(
        &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
        Zeroizing::new(random_scalar(&mut OsRng)),
      );

      let mut builder = SignableTransactionBuilder::new(
        rpc.get_protocol().await.unwrap(),
        rpc.get_fee().await.unwrap(),
        Some(Change::new(&change_view, false)),
      );
      builder.add_input(SpendableOutput::from(&rpc, outputs.swap_remove(0)).await.unwrap());

      // Send to a subaddress
      let sub_view = ViewPair::new(
        &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
        Zeroizing::new(random_scalar(&mut OsRng)),
      );
      builder.add_payment(
        sub_view
          .address(Network::Mainnet, AddressSpec::Subaddress(SubaddressIndex::new(0, 1).unwrap())),
        1,
      );
      (builder.build().unwrap(), (change_view, sub_view))
    },
    |_, tx: Transaction, _, views: (ViewPair, ViewPair)| async move {
      // Make sure the change can pick up its output
      let mut change_scanner = Scanner::from_view(views.0, Some(HashSet::new()));
      assert!(change_scanner.scan_transaction(&tx).not_locked().len() == 1);

      // Make sure the subaddress can pick up its output
      let mut sub_scanner = Scanner::from_view(views.1, Some(HashSet::new()));
      sub_scanner.register_subaddress(SubaddressIndex::new(0, 1).unwrap());
      let sub_outputs = sub_scanner.scan_transaction(&tx).not_locked();
      assert!(sub_outputs.len() == 1);
      assert_eq!(sub_outputs[0].commitment().amount, 1);

      // Make sure only one R was included in TX extra
      assert!(Extra::read::<&[u8]>(&mut tx.prefix.extra.as_ref())
        .unwrap()
        .keys()
        .unwrap()
        .1
        .is_none());
    },
  ),
);
