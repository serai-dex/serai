use monero_serai::{
  transaction::Transaction,
  wallet::SpendableOutput,
  rpc::{Rpc, OutputResponse},
  Protocol, DEFAULT_LOCK_WINDOW,
};

mod runner;

test!(
  select_latest_output_as_decoy,
  (
    // First make an initial tx0
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 2000000000000);
      (builder.build().unwrap(), ())
    },
    |rpc: Rpc<_>, tx: Transaction, mut scanner: Scanner, _| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 2000000000000);
      SpendableOutput::from(&rpc, output).await.unwrap()
    },
  ),
  (
    // Then make a second tx1
    |protocol: Protocol, rpc: Rpc<_>, mut builder: Builder, addr, state: _| async move {
      let output_tx0: SpendableOutput = state;
      let decoys = Decoys::select(
        &mut OsRng,
        &rpc,
        protocol.ring_len(),
        rpc.get_height().await.unwrap(),
        &[output_tx0.clone()],
      )
      .await
      .unwrap();

      let inputs = [output_tx0.clone()].into_iter().zip(decoys).collect::<Vec<_>>();
      builder.add_inputs(&inputs);
      builder.add_payment(addr, 1000000000000);

      (builder.build().unwrap(), (protocol, output_tx0))
    },
    // Then make sure DSA selects freshly unlocked output from tx1 as a decoy
    |rpc: Rpc<_>, tx: Transaction, mut scanner: Scanner, state: (_, _)| async move {
      use rand_core::OsRng;

      let height = rpc.get_height().await.unwrap();

      let output_tx1 =
        SpendableOutput::from(&rpc, scanner.scan_transaction(&tx).not_locked().swap_remove(0))
          .await
          .unwrap();

      // Make sure output from tx1 is in the block in which it unlocks
      let out_tx1: OutputResponse =
        rpc.get_outs(&[output_tx1.global_index]).await.unwrap().swap_remove(0);
      assert_eq!(out_tx1.height, height - DEFAULT_LOCK_WINDOW);
      assert!(out_tx1.unlocked);

      // Select decoys using spendable output from tx0 as the real, and make sure DSA selects
      // the freshly unlocked output from tx1 as a decoy
      let (protocol, output_tx0): (Protocol, SpendableOutput) = state;
      let mut selected_fresh_decoy = false;
      let mut attempts = 1000;
      while !selected_fresh_decoy && attempts > 0 {
        let decoys = Decoys::select(
          &mut OsRng, // TODO: use a seeded RNG to consistently select the latest output
          &rpc,
          protocol.ring_len(),
          height,
          &[output_tx0.clone()],
        )
        .await
        .unwrap();

        selected_fresh_decoy = decoys[0].indexes().contains(&output_tx1.global_index);
        attempts -= 1;
      }

      assert!(selected_fresh_decoy);
      assert_eq!(height, rpc.get_height().await.unwrap());
    },
  ),
);
