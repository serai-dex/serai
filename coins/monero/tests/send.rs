use monero_serai::{
  transaction::Transaction,
  wallet::{ReceivedOutput, SpendableOutput},
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
