use std::{
  time::{Duration, SystemTime},
  collections::HashMap,
};

use ciphersuite::{Ciphersuite, Ristretto};
use dkg::{Participant, ThresholdParams};

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
};
use messages::{key_gen::KeyGenId, CoordinatorMessage};

use dockertest::DockerTest;

use crate::*;

pub(crate) const COORDINATORS: usize = 4;
// pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

fn new_test() -> (Vec<(Handles, <Ristretto as Ciphersuite>::F)>, DockerTest) {
  let mut coordinators = vec![];
  let mut test = DockerTest::new();
  for i in 0 .. COORDINATORS {
    let (handles, coord_key, compositions) = coordinator_stack(match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    });
    coordinators.push((handles, coord_key));
    for composition in compositions {
      test.add_composition(composition);
    }
  }
  (coordinators, test)
}

#[tokio::test]
async fn key_gen_test() {
  let (processors, test) = new_test();

  let participant_from_i = |i: usize| Participant::new(u16::try_from(i + 1).unwrap()).unwrap();

  test
    .run_async(|ops| async move {
      // Wait for the Serai node to boot, and for the Tendermint chain to get past the first block
      // TODO: Replace this with a Coordinator RPC
      tokio::time::sleep(Duration::from_secs(150)).await;

      // Sleep even longer if in the CI due to it being slower than commodity hardware
      if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
        tokio::time::sleep(Duration::from_secs(120)).await;
      }

      // Connect to the Message Queues as the processor
      let mut new_processors: Vec<Processor> = vec![];
      for (handles, key) in processors {
        new_processors.push(Processor::new(NetworkId::Bitcoin, &ops, handles, key).await);
      }
      let mut processors = new_processors;

      let set = ValidatorSet { session: Session(0), network: NetworkId::Bitcoin };
      let id = KeyGenId { set, attempt: 0 };

      for (i, processor) in processors.iter_mut().enumerate() {
        assert_eq!(
          processor.recv_message().await,
          CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
            id,
            params: ThresholdParams::new(
              u16::try_from(((COORDINATORS * 2) / 3) + 1).unwrap(),
              u16::try_from(COORDINATORS).unwrap(),
              participant_from_i(i),
            )
            .unwrap()
          })
        );

        processor
          .send_message(messages::key_gen::ProcessorMessage::Commitments {
            id,
            commitments: vec![u8::try_from(i).unwrap()],
          })
          .await;
      }

      // Sleep for 20s to give everything processing time
      tokio::time::sleep(Duration::from_secs(20)).await;
      for (i, processor) in processors.iter_mut().enumerate() {
        let mut commitments = (0 .. u8::try_from(COORDINATORS).unwrap())
          .map(|l| (participant_from_i(l.into()), vec![l]))
          .collect::<HashMap<_, _>>();
        commitments.remove(&participant_from_i(i));
        assert_eq!(
          processor.recv_message().await,
          CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::Commitments {
            id,
            commitments,
          })
        );

        // from (0 .. n), to (1 ..= n)
        let mut shares = (0 .. u8::try_from(COORDINATORS).unwrap())
          .map(|l| (participant_from_i(l.into()), vec![u8::try_from(i).unwrap(), l + 1]))
          .collect::<HashMap<_, _>>();

        let i = participant_from_i(i);
        shares.remove(&i);
        processor.send_message(messages::key_gen::ProcessorMessage::Shares { id, shares }).await;
      }

      tokio::time::sleep(Duration::from_secs(20)).await;
      for (i, processor) in processors.iter_mut().enumerate() {
        let i = participant_from_i(i);
        assert_eq!(
          processor.recv_message().await,
          CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::Shares {
            id,
            shares: {
              let mut shares = (0 .. u8::try_from(COORDINATORS).unwrap())
                .map(|l| {
                  (participant_from_i(l.into()), vec![l, u8::try_from(u16::from(i)).unwrap()])
                })
                .collect::<HashMap<_, _>>();
              shares.remove(&i);
              shares
            },
          })
        );

        processor
          .send_message(messages::key_gen::ProcessorMessage::GeneratedKeyPair {
            id,
            substrate_key: [0xaa; 32],
            network_key: b"network_key".to_vec(),
          })
          .await;
      }

      // Sleeps for longer since we need to wait for a Substrate block as well
      tokio::time::sleep(Duration::from_secs(60)).await;
      let mut message = None;
      for processor in processors.iter_mut() {
        let msg = processor.recv_message().await;
        if message.is_none() {
          match msg {
            CoordinatorMessage::Substrate(
              messages::substrate::CoordinatorMessage::ConfirmKeyPair {
                context,
                set: this_set,
                ref key_pair,
              },
            ) => {
              assert!(
                SystemTime::now()
                  .duration_since(SystemTime::UNIX_EPOCH)
                  .unwrap()
                  .as_secs()
                  .abs_diff(context.serai_time) <
                  70
              );
              assert_eq!(context.network_latest_finalized_block.0, [0; 32]);
              assert_eq!(set, this_set);
              assert_eq!(key_pair.0 .0, [0xaa; 32]);
              assert_eq!(key_pair.1.to_vec(), b"network_key".to_vec());
            }
            _ => panic!("coordinator didn't respond with ConfirmKeyPair"),
          }
          message = Some(msg);
        } else {
          assert_eq!(message, Some(msg));
        }
      }
    })
    .await;

  // TODO: Check Substrate actually has this key pair
}
