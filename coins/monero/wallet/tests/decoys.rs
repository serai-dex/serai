use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{
  DEFAULT_LOCK_WINDOW,
  transaction::Transaction,
  rpc::{OutputResponse, Rpc},
  WalletOutput,
};

mod runner;

test!(
  select_latest_output_as_decoy_canonical,
  (
    // First make an initial tx0
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 2000000000000);
      (builder.build().unwrap(), ())
    },
    |rpc, block, tx: Transaction, mut scanner: Scanner, ()| async move {
      let output =
        scanner.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 2000000000000);
      output
    },
  ),
  (
    // Then make a second tx1
    |rct_type: RctType, rpc: SimpleRequestRpc, mut builder: Builder, addr, state: _| async move {
      let output_tx0: WalletOutput = state;

      let input = OutputWithDecoys::fingerprintable_deterministic_new(
        &mut OsRng,
        &rpc,
        ring_len(rct_type),
        rpc.get_height().await.unwrap(),
        output_tx0.clone(),
      )
      .await
      .unwrap();
      builder.add_input(input);
      builder.add_payment(addr, 1000000000000);

      (builder.build().unwrap(), (rct_type, output_tx0))
    },
    // Then make sure DSA selects freshly unlocked output from tx1 as a decoy
    |rpc, _, tx: Transaction, _: Scanner, state: (_, _)| async move {
      use rand_core::OsRng;

      let rpc: SimpleRequestRpc = rpc;

      let height = rpc.get_height().await.unwrap();

      let most_recent_o_index = rpc.get_o_indexes(tx.hash()).await.unwrap().pop().unwrap();

      // Make sure output from tx1 is in the block in which it unlocks
      let out_tx1: OutputResponse =
        rpc.get_outs(&[most_recent_o_index]).await.unwrap().swap_remove(0);
      assert_eq!(out_tx1.height, height - DEFAULT_LOCK_WINDOW);
      assert!(out_tx1.unlocked);

      // Select decoys using spendable output from tx0 as the real, and make sure DSA selects
      // the freshly unlocked output from tx1 as a decoy
      let (rct_type, output_tx0): (RctType, WalletOutput) = state;
      let mut selected_fresh_decoy = false;
      let mut attempts = 1000;
      while !selected_fresh_decoy && attempts > 0 {
        let decoys = OutputWithDecoys::fingerprintable_deterministic_new(
          &mut OsRng, // TODO: use a seeded RNG to consistently select the latest output
          &rpc,
          ring_len(rct_type),
          height,
          output_tx0.clone(),
        )
        .await
        .unwrap()
        .decoys()
        .clone();

        selected_fresh_decoy = decoys.positions().contains(&most_recent_o_index);
        attempts -= 1;
      }

      assert!(selected_fresh_decoy);
      assert_eq!(height, rpc.get_height().await.unwrap());
    },
  ),
);

test!(
  select_latest_output_as_decoy,
  (
    // First make an initial tx0
    |_, mut builder: Builder, addr| async move {
      builder.add_payment(addr, 2000000000000);
      (builder.build().unwrap(), ())
    },
    |rpc: SimpleRequestRpc, block, tx: Transaction, mut scanner: Scanner, ()| async move {
      let output =
        scanner.scan(&rpc, &block).await.unwrap().not_additionally_locked().swap_remove(0);
      assert_eq!(output.transaction(), tx.hash());
      assert_eq!(output.commitment().amount, 2000000000000);
      output
    },
  ),
  (
    // Then make a second tx1
    |rct_type: RctType, rpc, mut builder: Builder, addr, output_tx0: WalletOutput| async move {
      let rpc: SimpleRequestRpc = rpc;

      let input = OutputWithDecoys::new(
        &mut OsRng,
        &rpc,
        ring_len(rct_type),
        rpc.get_height().await.unwrap(),
        output_tx0.clone(),
      )
      .await
      .unwrap();
      builder.add_input(input);
      builder.add_payment(addr, 1000000000000);

      (builder.build().unwrap(), (rct_type, output_tx0))
    },
    // Then make sure DSA selects freshly unlocked output from tx1 as a decoy
    |rpc, _, tx: Transaction, _: Scanner, state: (_, _)| async move {
      use rand_core::OsRng;

      let rpc: SimpleRequestRpc = rpc;

      let height = rpc.get_height().await.unwrap();

      let most_recent_o_index = rpc.get_o_indexes(tx.hash()).await.unwrap().pop().unwrap();

      // Make sure output from tx1 is in the block in which it unlocks
      let out_tx1: OutputResponse =
        rpc.get_outs(&[most_recent_o_index]).await.unwrap().swap_remove(0);
      assert_eq!(out_tx1.height, height - DEFAULT_LOCK_WINDOW);
      assert!(out_tx1.unlocked);

      // Select decoys using spendable output from tx0 as the real, and make sure DSA selects
      // the freshly unlocked output from tx1 as a decoy
      let (rct_type, output_tx0): (RctType, WalletOutput) = state;
      let mut selected_fresh_decoy = false;
      let mut attempts = 1000;
      while !selected_fresh_decoy && attempts > 0 {
        let decoys = OutputWithDecoys::new(
          &mut OsRng, // TODO: use a seeded RNG to consistently select the latest output
          &rpc,
          ring_len(rct_type),
          height,
          output_tx0.clone(),
        )
        .await
        .unwrap()
        .decoys()
        .clone();

        selected_fresh_decoy = decoys.positions().contains(&most_recent_o_index);
        attempts -= 1;
      }

      assert!(selected_fresh_decoy);
      assert_eq!(height, rpc.get_height().await.unwrap());
    },
  ),
);
