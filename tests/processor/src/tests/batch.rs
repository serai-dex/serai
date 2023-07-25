use std::collections::HashMap;

use dkg::{Participant, tests::clone_without};

use serai_primitives::{NetworkId, BlockHash, crypto::RuntimePublic, PublicKey};
use serai_in_instructions_primitives::batch_message;

use dockertest::DockerTest;

use crate::{*, tests::*};

#[test]
fn batch_test() {
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

      // Create a wallet before we start generating keys
      let mut wallet = Wallet::new(network, &ops, coordinators[0].network_handle.clone()).await;
      coordinators[0].sync(&ops, &coordinators[1 ..]).await;

      // Generate keys
      let key_pair = key_gen(&mut coordinators, network).await;

      // Now we we have to mine blocks to activate the key
      // (the first key is activated when the coin's block time exceeds the Serai time it was
      // confirmed at)

      for _ in 0 .. confirmations(network) {
        coordinators[0].add_block(&ops).await;
      }
      coordinators[0].sync(&ops, &coordinators[1 ..]).await;

      // Send into the processor's wallet
      let tx = wallet.send_to_address(&ops, &key_pair.1).await;
      for coordinator in &coordinators {
        coordinator.publish_transacton(&ops, &tx).await;
      }

      // Put the TX past the confirmation depth
      let mut block_with_tx = None;
      for _ in 0 .. confirmations(network) {
        let (hash, _) = coordinators[0].add_block(&ops).await;
        if block_with_tx.is_none() {
          block_with_tx = Some(hash);
        }
      }
      coordinators[0].sync(&ops, &coordinators[1 ..]).await;

      // Sleep for 10s
      // The scanner works on a 5s interval, so this leaves a few s for any processing/latency
      tokio::time::sleep(core::time::Duration::from_secs(10)).await;

      // Make sure the proceessors picked it up by checking they're trying to sign a batch for it
      let mut id = None;
      let mut preprocesses = HashMap::new();
      for (i, coordinator) in coordinators.iter_mut().enumerate() {
        // Only use their preprocess if they're within the threshold
        let i = if i < THRESHOLD {
          Some(Participant::new(u16::try_from(i).unwrap() + 1).unwrap())
        } else {
          None
        };

        let msg = coordinator.recv_message().await;
        match msg {
          messages::ProcessorMessage::Coordinator(
            messages::coordinator::ProcessorMessage::BatchPreprocess { id: this_id, preprocess },
          ) => {
            assert_eq!(&this_id.key, &key_pair.0 .0);
            assert_eq!(this_id.attempt, 0);

            if id.is_none() {
              id = Some(this_id.clone());
            }
            assert_eq!(&this_id, id.as_ref().unwrap());

            if let Some(i) = i {
              preprocesses.insert(i, preprocess);
            }
          }
          _ => panic!("processor didn't send batch preprocess"),
        }
      }
      let id = id.unwrap();

      // Continue with batch siging by sending the preprocesses to selected parties
      for (i, coordinator) in coordinators.iter_mut().enumerate().take(THRESHOLD) {
        let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

        coordinator
          .send_message(messages::coordinator::CoordinatorMessage::BatchPreprocesses {
            id: id.clone(),
            preprocesses: clone_without(&preprocesses, &i),
          })
          .await;
      }

      let mut shares = HashMap::new();
      for (i, coordinator) in coordinators.iter_mut().enumerate().take(THRESHOLD) {
        let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

        match coordinator.recv_message().await {
          messages::ProcessorMessage::Coordinator(
            messages::coordinator::ProcessorMessage::BatchShare { id: this_id, share },
          ) => {
            assert_eq!(&this_id, &id);
            shares.insert(i, share);
          }
          _ => panic!("processor didn't send batch share"),
        }
      }

      for (i, coordinator) in coordinators.iter_mut().enumerate().take(THRESHOLD) {
        let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

        coordinator
          .send_message(messages::coordinator::CoordinatorMessage::BatchShares {
            id: id.clone(),
            shares: clone_without(&shares, &i),
          })
          .await;
      }

      // The selected processors should yield the batch
      for coordinator in coordinators.iter_mut().take(THRESHOLD) {
        match coordinator.recv_message().await {
          messages::ProcessorMessage::Substrate(
            messages::substrate::ProcessorMessage::Update { key, batch },
          ) => {
            assert_eq!(&key, &key_pair.0 .0);

            assert_eq!(batch.batch.network, network);
            assert_eq!(batch.batch.id, 0);
            assert!(PublicKey::from_raw(key_pair.0 .0)
              .verify(&batch_message(&batch.batch), &batch.signature));
            assert_eq!(batch.batch.block, BlockHash(block_with_tx.unwrap()));
            // This shouldn't have an instruction as we didn't add any data into the TX we sent
            assert!(batch.batch.instructions.is_empty());
          }
          _ => panic!("processor didn't send batch"),
        }
      }
    });
  }
}
