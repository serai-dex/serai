use rand_core::OsRng;

use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{
  transaction::Transaction, Protocol, rpc::Rpc, extra::Extra, address::SubaddressIndex,
  ReceivedOutput, SpendableOutput, DecoySelection, Decoys, SignableTransactionBuilder,
};

mod runner;

// Set up inputs, select decoys, then add them to the TX builder
async fn add_inputs(
  protocol: Protocol,
  rpc: &SimpleRequestRpc,
  outputs: Vec<ReceivedOutput>,
  builder: &mut SignableTransactionBuilder,
) {
  let mut spendable_outputs = Vec::with_capacity(outputs.len());
  for output in outputs {
    spendable_outputs.push(SpendableOutput::from(rpc, output).await.unwrap());
  }

  let decoys = Decoys::fingerprintable_canonical_select(
    &mut OsRng,
    rpc,
    protocol.ring_len(),
    rpc.get_height().await.unwrap(),
    &spendable_outputs,
  )
  .await
  .unwrap();

  let inputs = spendable_outputs.into_iter().zip(decoys).collect::<Vec<_>>();

  builder.add_inputs(&inputs);
}

test!(
  spend_miner_output,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 5);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
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
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      assert_eq!(outputs[1].commitment().amount, 2000000000000);
      outputs
    },
  ),
  (
    |protocol: Protocol, rpc, mut builder: Builder, addr, outputs: Vec<ReceivedOutput>| async move {
      add_inputs(protocol, &rpc, outputs, &mut builder).await;
      builder.add_payment(addr, 6);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
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
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      outputs
    },
  ),
  (
    |protocol, rpc: SimpleRequestRpc, _, _, outputs: Vec<ReceivedOutput>| async move {
      use monero_wallet::FeePriority;

      let change_view = ViewPair::new(
        &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
        Zeroizing::new(Scalar::random(&mut OsRng)),
      );

      let mut builder = SignableTransactionBuilder::new(
        protocol,
        rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
        Change::new(&change_view, false),
      );
      add_inputs(protocol, &rpc, vec![outputs.first().unwrap().clone()], &mut builder).await;

      // Send to a subaddress
      let sub_view = ViewPair::new(
        &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
        Zeroizing::new(Scalar::random(&mut OsRng)),
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
      assert!(Extra::read::<&[u8]>(&mut tx.prefix().extra.as_ref())
        .unwrap()
        .keys()
        .unwrap()
        .1
        .is_none());
    },
  ),
);

test!(
  spend_one_input_to_one_output_plus_change,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 2000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 2000000000000);
      outputs
    },
  ),
  (
    |protocol: Protocol, rpc, mut builder: Builder, addr, outputs: Vec<ReceivedOutput>| async move {
      add_inputs(protocol, &rpc, outputs, &mut builder).await;
      builder.add_payment(addr, 2);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 2);
    },
  ),
);

test!(
  spend_max_outputs,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 1000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      outputs
    },
  ),
  (
    |protocol: Protocol, rpc, mut builder: Builder, addr, outputs: Vec<ReceivedOutput>| async move {
      add_inputs(protocol, &rpc, outputs, &mut builder).await;

      for i in 0 .. 15 {
        builder.add_payment(addr, i + 1);
      }
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut scanned_tx = scanner.scan_transaction(&tx).not_locked();

      let mut output_amounts = HashSet::new();
      for i in 0 .. 15 {
        output_amounts.insert(i + 1);
      }
      for _ in 0 .. 15 {
        let output = scanned_tx.swap_remove(0);
        let amount = output.commitment().amount;
        assert!(output_amounts.contains(&amount));
        output_amounts.remove(&amount);
      }
    },
  ),
);

test!(
  spend_max_outputs_to_subaddresses,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 1000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      outputs
    },
  ),
  (
    |protocol: Protocol, rpc, mut builder: Builder, _, outputs: Vec<ReceivedOutput>| async move {
      add_inputs(protocol, &rpc, outputs, &mut builder).await;

      let view = runner::random_address().1;
      let mut scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));

      let mut subaddresses = vec![];
      for i in 0 .. 15 {
        let subaddress = SubaddressIndex::new(0, i + 1).unwrap();
        scanner.register_subaddress(subaddress);

        builder.add_payment(
          view.address(Network::Mainnet, AddressSpec::Subaddress(subaddress)),
          u64::from(i + 1),
        );
        subaddresses.push(subaddress);
      }

      (builder.build().unwrap(), (scanner, subaddresses))
    },
    |_, tx: Transaction, _, mut state: (Scanner, Vec<SubaddressIndex>)| async move {
      use std::collections::HashMap;

      let mut scanned_tx = state.0.scan_transaction(&tx).not_locked();

      let mut output_amounts_by_subaddress = HashMap::new();
      for i in 0 .. 15 {
        output_amounts_by_subaddress.insert(u64::try_from(i + 1).unwrap(), state.1[i]);
      }
      for _ in 0 .. 15 {
        let output = scanned_tx.swap_remove(0);
        let amount = output.commitment().amount;

        assert!(output_amounts_by_subaddress.contains_key(&amount));
        assert_eq!(output.metadata.subaddress, Some(output_amounts_by_subaddress[&amount]));

        output_amounts_by_subaddress.remove(&amount);
      }
    },
  ),
);

test!(
  spend_one_input_to_two_outputs_no_change,
  (
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 1000000000000);
      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 1000000000000);
      outputs
    },
  ),
  (
    |protocol, rpc: SimpleRequestRpc, _, addr, outputs: Vec<ReceivedOutput>| async move {
      use monero_wallet::FeePriority;

      let mut builder = SignableTransactionBuilder::new(
        protocol,
        rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
        Change::fingerprintable(None),
      );
      add_inputs(protocol, &rpc, vec![outputs.first().unwrap().clone()], &mut builder).await;
      builder.add_payment(addr, 10000);
      builder.add_payment(addr, 50000);

      (builder.build().unwrap(), ())
    },
    |_, tx: Transaction, mut scanner: Scanner, ()| async move {
      let mut outputs = scanner.scan_transaction(&tx).not_locked();
      outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount));
      assert_eq!(outputs[0].commitment().amount, 10000);
      assert_eq!(outputs[1].commitment().amount, 50000);

      // The remainder should get shunted to fee, which is fingerprintable
      let Transaction::V2 { proofs: Some(ref proofs), .. } = tx else { panic!("TX wasn't RingCT") };
      assert_eq!(proofs.base.fee, 1000000000000 - 10000 - 50000);
    },
  ),
);
