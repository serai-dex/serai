use std::time::Duration;

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
async fn stack_test() {
  let (processors, test) = new_test();

  test
    .run_async(|ops| async move {
      // Wait for the Serai node to boot
      tokio::time::sleep(Duration::from_secs(30)).await;

      // Connect to the Message Queues as the processor
      let mut new_processors: Vec<Processor> = vec![];
      for (handles, key) in processors {
        new_processors.push(Processor::new(NetworkId::Bitcoin, &ops, handles, key).await);
      }
      let mut processors = new_processors;

      for (i, processor) in processors.iter_mut().enumerate() {
        assert_eq!(
          processor.recv_message().await,
          CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
            id: KeyGenId {
              set: ValidatorSet { session: Session(0), network: NetworkId::Bitcoin },
              attempt: 0
            },
            params: ThresholdParams::new(
              3,
              4,
              Participant::new(u16::try_from(i).unwrap() + 1).unwrap()
            )
            .unwrap()
          })
        );
      }

      tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;
}
