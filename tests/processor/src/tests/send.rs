use std::{
  collections::HashMap,
  time::{SystemTime, Duration},
};

use dkg::{Participant, tests::clone_without};

use messages::{sign::SignId, SubstrateContext};

use serai_client::{
  primitives::{BlockHash, NetworkId},
  tokens::primitives::{OutInstruction, OutInstructionWithBalance},
};

use crate::{*, tests::*};

#[allow(unused)]
pub(crate) async fn recv_sign_preprocesses(
  coordinators: &mut [Coordinator],
  key: [u8; 32],
  attempt: u32,
) -> (SignId, HashMap<Participant, Vec<u8>>) {
  let mut id = None;
  let mut preprocesses = HashMap::new();
  for (i, coordinator) in coordinators.iter_mut().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

    let msg = coordinator.recv_message().await;
    match msg {
      messages::ProcessorMessage::Sign(messages::sign::ProcessorMessage::Preprocess {
        id: this_id,
        preprocess,
      }) => {
        if id.is_none() {
          assert_eq!(&this_id.key, &key);
          assert_eq!(this_id.attempt, attempt);
          id = Some(this_id.clone());
        }
        assert_eq!(&this_id, id.as_ref().unwrap());

        preprocesses.insert(i, preprocess);
      }
      _ => panic!("processor didn't send sign preprocess"),
    }
  }

  // Reduce the preprocesses down to the threshold
  while preprocesses.len() > THRESHOLD {
    preprocesses.remove(
      &Participant::new(
        u16::try_from(OsRng.next_u64() % u64::try_from(COORDINATORS).unwrap()).unwrap() + 1,
      )
      .unwrap(),
    );
  }

  (id.unwrap(), preprocesses)
}

#[allow(unused)]
pub(crate) async fn sign_tx(
  coordinators: &mut [Coordinator],
  id: SignId,
  preprocesses: HashMap<Participant, Vec<u8>>,
) -> Vec<u8> {
  assert_eq!(preprocesses.len(), THRESHOLD);

  for (i, coordinator) in coordinators.iter_mut().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

    if preprocesses.contains_key(&i) {
      coordinator
        .send_message(messages::sign::CoordinatorMessage::Preprocesses {
          id: id.clone(),
          preprocesses: clone_without(&preprocesses, &i),
        })
        .await;
    }
  }

  let mut shares = HashMap::new();
  for (i, coordinator) in coordinators.iter_mut().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

    if preprocesses.contains_key(&i) {
      match coordinator.recv_message().await {
        messages::ProcessorMessage::Sign(messages::sign::ProcessorMessage::Share {
          id: this_id,
          share,
        }) => {
          assert_eq!(&this_id, &id);
          shares.insert(i, share);
        }
        _ => panic!("processor didn't send TX shares"),
      }
    }
  }

  for (i, coordinator) in coordinators.iter_mut().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

    if preprocesses.contains_key(&i) {
      coordinator
        .send_message(messages::sign::CoordinatorMessage::Shares {
          id: id.clone(),
          shares: clone_without(&shares, &i),
        })
        .await;
    }
  }

  // The selected processors should yield Completed
  let mut tx = None;
  for (i, coordinator) in coordinators.iter_mut().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();

    if preprocesses.contains_key(&i) {
      match coordinator.recv_message().await {
        messages::ProcessorMessage::Sign(messages::sign::ProcessorMessage::Completed {
          key,
          id: this_id,
          tx: this_tx,
        }) => {
          assert_eq!(&key, &id.key);
          assert_eq!(&this_id, &id.id);

          if tx.is_none() {
            tx = Some(this_tx.clone());
          }

          assert_eq!(tx.as_ref().unwrap(), &this_tx);
        }
        _ => panic!("processor didn't send Completed"),
      }
    }
  }
  tx.unwrap()
}

#[test]
fn send_test() {
  for network in [NetworkId::Bitcoin, NetworkId::Monero] {
    let (coordinators, test) = new_test(network);

    test.run(|ops| async move {
      tokio::time::sleep(Duration::from_secs(1)).await;

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
      let (tx, balance_sent) = wallet.send_to_address(&ops, &key_pair.1, None).await;
      for coordinator in &mut coordinators {
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
      tokio::time::sleep(Duration::from_secs(10)).await;

      // Make sure the proceessors picked it up by checking they're trying to sign a batch for it
      let (id, preprocesses) = recv_batch_preprocesses(&mut coordinators, key_pair.0 .0, 0).await;

      // Continue with signing the batch
      let batch = sign_batch(&mut coordinators, id, preprocesses).await;

      // Check it
      assert_eq!(batch.batch.network, network);
      assert_eq!(batch.batch.id, 0);
      assert_eq!(batch.batch.block, BlockHash(block_with_tx.unwrap()));
      assert!(batch.batch.instructions.is_empty());

      // Fire a SubstrateBlock with a burn
      let substrate_block_num = (OsRng.next_u64() % 4_000_000_000u64) + 1;
      let serai_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

      for coordinator in &mut coordinators {
        substrate_block(
          coordinator,
          messages::substrate::CoordinatorMessage::SubstrateBlock {
            context: SubstrateContext {
              serai_time,
              coin_latest_finalized_block: batch.batch.block,
            },
            network,
            block: substrate_block_num,
            // TODO: Should we use the network key here? Or should we only use the Ristretto key?
            key: key_pair.1.to_vec(),
            burns: vec![OutInstructionWithBalance {
              instruction: OutInstruction { address: wallet.address(), data: None },
              balance: balance_sent,
            }],
          },
        )
        .await;
      }

      /*
        // Trigger a random amount of re-attempts
        for attempt in 1 ..= u32::try_from(OsRng.next_u64() % 4).unwrap() {
          // TODO: Double check how the processor handles this ID field
          // It should be able to assert its perfectly sequential
          id.attempt = attempt;
          for coordinator in coordinators.iter_mut() {
            coordinator
              .send_message(messages::sign::CoordinatorMessage::Reattempt {
                id: id.clone(),
              })
              .await;
          }
          (id, preprocesses) =
            recv_batch_preprocesses(&mut coordinators, key_pair.0 .0, attempt).await;
        }
      */
    });
  }
}
