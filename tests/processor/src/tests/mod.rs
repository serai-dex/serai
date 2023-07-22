use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use dkg::{Participant, ThresholdParams, tests::clone_without};

use serai_primitives::NetworkId;
use serai_validator_sets_primitives::{Session, ValidatorSet};

use serai_message_queue::{Service, Metadata, client::MessageQueue};

use dockertest::{DockerOperations, DockerTest};

use crate::*;

const COORDINATORS: usize = 4;
const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

fn coordinator_queue(
  ops: &DockerOperations,
  handle: String,
  coord_key: <Ristretto as Ciphersuite>::F,
) -> MessageQueue {
  let rpc = ops.handle(&handle).host_port(2287).unwrap();
  let rpc = rpc.0.to_string() + ":" + &rpc.1.to_string();
  MessageQueue::new(Service::Coordinator, rpc, Zeroizing::new(coord_key))
}

// Receive a message from a processor via its coordinator
async fn recv_message(
  coordinator: &MessageQueue,
  from: NetworkId,
  id: u64,
) -> messages::ProcessorMessage {
  let msg =
    tokio::time::timeout(core::time::Duration::from_secs(10), coordinator.next(id)).await.unwrap();
  assert_eq!(msg.from, Service::Processor(from));
  assert_eq!(msg.id, id);
  coordinator.ack(id).await;
  serde_json::from_slice(&msg.msg).unwrap()
}

// Perform an interaction with all processors via their coordinators
async fn interact_with_all<
  FS: Fn(Participant) -> messages::key_gen::CoordinatorMessage,
  FR: FnMut(Participant, messages::key_gen::ProcessorMessage),
>(
  id: u64,
  coordinators: &[MessageQueue],
  network: NetworkId,
  message: FS,
  mut recv: FR,
) {
  for (i, coordinator) in coordinators.iter().enumerate() {
    let participant = Participant::new(u16::try_from(i + 1).unwrap()).unwrap();
    coordinator
      .queue(
        Metadata {
          from: Service::Coordinator,
          to: Service::Processor(network),
          intent: id.to_le_bytes().to_vec(),
        },
        serde_json::to_string(&messages::CoordinatorMessage::KeyGen(message(participant)))
          .unwrap()
          .into_bytes(),
      )
      .await;

    match recv_message(coordinator, network, id).await {
      messages::ProcessorMessage::KeyGen(msg) => recv(participant, msg),
      _ => panic!("processor didn't return KeyGen message"),
    }
  }
}

#[test]
fn key_gen() {
  for network in [NetworkId::Bitcoin, NetworkId::Monero] {
    let mut coordinators = vec![];
    let mut test = DockerTest::new();
    for _ in 0 .. COORDINATORS {
      let (coord_handle, coord_key, compositions) = processor_stack(network);
      coordinators.push((coord_handle, coord_key));
      for composition in compositions {
        test.add_composition(composition);
      }
    }

    test.run(|ops| async move {
      // Sleep for a second for the message-queue to boot
      // It isn't an error to start immediately, it just silences an error
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;

      // Connect to the Message Queues as the coordinator
      let coordinators = coordinators
        .into_iter()
        .map(|(handle, key)| coordinator_queue(&ops, handle, key))
        .collect::<Vec<_>>();

      // Order a key gen
      let id = messages::key_gen::KeyGenId {
        set: ValidatorSet { session: Session(0), network },
        attempt: 0,
      };

      let mut commitments = HashMap::new();
      interact_with_all(
        0,
        &coordinators,
        network,
        |participant| messages::key_gen::CoordinatorMessage::GenerateKey {
          id,
          params: ThresholdParams::new(
            u16::try_from(THRESHOLD).unwrap(),
            u16::try_from(COORDINATORS).unwrap(),
            participant,
          )
          .unwrap(),
        },
        |participant, msg| match msg {
          messages::key_gen::ProcessorMessage::Commitments {
            id: this_id,
            commitments: these_commitments,
          } => {
            assert_eq!(this_id, id);
            commitments.insert(participant, these_commitments);
          }
          _ => panic!("processor didn't return Commitments in response to GenerateKey"),
        },
      )
      .await;

      // Send the commitments to all parties
      let mut shares = HashMap::new();
      interact_with_all(
        1,
        &coordinators,
        network,
        |participant| messages::key_gen::CoordinatorMessage::Commitments {
          id,
          commitments: clone_without(&commitments, &participant),
        },
        |participant, msg| match msg {
          messages::key_gen::ProcessorMessage::Shares { id: this_id, shares: these_shares } => {
            assert_eq!(this_id, id);
            shares.insert(participant, these_shares);
          }
          _ => panic!("processor didn't return Shares in response to GenerateKey"),
        },
      )
      .await;

      // Send the shares
      let mut substrate_key = None;
      let mut coin_key = None;
      interact_with_all(
        2,
        &coordinators,
        network,
        |participant| messages::key_gen::CoordinatorMessage::Shares {
          id,
          shares: shares
            .iter()
            .filter_map(|(this_participant, shares)| {
              shares.get(&participant).cloned().map(|share| (*this_participant, share))
            })
            .collect(),
        },
        |_, msg| match msg {
          messages::key_gen::ProcessorMessage::GeneratedKeyPair {
            id: this_id,
            substrate_key: this_substrate_key,
            coin_key: this_coin_key,
          } => {
            assert_eq!(this_id, id);
            if substrate_key.is_none() {
              substrate_key = Some(this_substrate_key);
              coin_key = Some(this_coin_key.clone());
            }
            assert_eq!(substrate_key.unwrap(), this_substrate_key);
            assert_eq!(coin_key.as_ref().unwrap(), &this_coin_key);
          }
          _ => panic!("processor didn't return GeneratedKeyPair in response to GenerateKey"),
        },
      )
      .await;
    });
  }
}
