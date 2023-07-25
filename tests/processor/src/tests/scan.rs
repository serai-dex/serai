use serai_primitives::NetworkId;

use dockertest::DockerTest;

use crate::{*, tests::*};

#[test]
fn scan_test() {
  for network in [NetworkId::Bitcoin, NetworkId::Monero] {
    let mut coordinators = vec![];
    let mut test = DockerTest::new();
    for _ in 0 .. COORDINATORS {
      let (handles, coord_key, compositions) = processor_stack(network);
      coordinators.push((handles, coord_key));
      for composition in compositions {
        test.add_composition(composition);
      }
    }

    test.run(|ops| async move {
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;

      let mut coordinators = coordinators
        .into_iter()
        .map(|(handles, key)| Coordinator::new(network, &ops, handles, key))
        .collect::<Vec<_>>();

      // Start by generating keys
      let key_pair = key_gen(&mut coordinators, network).await;

      // Now we we have to mine blocks to activate the key
      // (the first key is activated when the coin's block time exceeds the Serai time it was
      // confirmed at)

      for _ in 0 .. confirmations(network) {
        let block = coordinators[0].add_block(&ops).await;
        for coordinator in &coordinators[1 ..] {
          coordinator.broadcast_block(&ops, &block).await;
        }
      }

      // Send into the processor's wallet
      let mut wallet = Wallet::new(network, &ops, coordinators[0].network_handle.clone()).await;
      coordinators[0].sync(&ops, &coordinators[1 ..]).await;
      let tx = wallet.send_to_address(&ops, &key_pair.1).await;
      for coordinator in &coordinators {
        coordinator.publish_transacton(&ops, &tx).await;
      }

      // Put the TX past the confirmation depth
      for _ in 0 .. confirmations(network) {
        let block = coordinators[0].add_block(&ops).await;
        for coordinator in &coordinators[1 ..] {
          coordinator.broadcast_block(&ops, &block).await;
        }
      }

      tokio::time::sleep(core::time::Duration::from_secs(10)).await;

      // Make sure the coordinators picked it up by checking they're trying to sign a batch for it
      for coordinator in &mut coordinators {
        let msg = coordinator.recv_message().await;
        match msg {
          messages::ProcessorMessage::Coordinator(
            messages::coordinator::ProcessorMessage::BatchPreprocess { id, .. },
          ) => {
            assert_eq!(&id.key, &key_pair.0 .0);
            assert_eq!(id.attempt, 0);
          }
          _ => panic!("processor didn't send batch preprocess"),
        }
      }
    });
  }
}
