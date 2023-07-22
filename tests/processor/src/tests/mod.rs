use std::{collections::HashMap, time::SystemTime};

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use dkg::{Participant, ThresholdParams, tests::clone_without};

use serai_primitives::{NetworkId, BlockHash, PublicKey};
use serai_validator_sets_primitives::{Session, ValidatorSet};

use messages::{SubstrateContext, key_gen::KeyGenId, CoordinatorMessage, ProcessorMessage};

use serai_message_queue::{Service, Metadata, client::MessageQueue};

use dockertest::{DockerOperations, DockerTest};

use crate::*;

const COORDINATORS: usize = 4;
const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

struct Coordinator {
  next_send_id: u64,
  next_recv_id: u64,
  queue: MessageQueue,
}

fn coordinator_queue(
  ops: &DockerOperations,
  handle: String,
  coord_key: <Ristretto as Ciphersuite>::F,
) -> Coordinator {
  let rpc = ops.handle(&handle).host_port(2287).unwrap();
  let rpc = rpc.0.to_string() + ":" + &rpc.1.to_string();
  Coordinator {
    next_send_id: 0,
    next_recv_id: 0,
    queue: MessageQueue::new(Service::Coordinator, rpc, Zeroizing::new(coord_key)),
  }
}

// Send a message to a processor via its coordinator
async fn send_message(coordinator: &mut Coordinator, network: NetworkId, msg: CoordinatorMessage) {
  coordinator
    .queue
    .queue(
      Metadata {
        from: Service::Coordinator,
        to: Service::Processor(network),
        intent: coordinator.next_send_id.to_le_bytes().to_vec(),
      },
      serde_json::to_string(&msg).unwrap().into_bytes(),
    )
    .await;
  coordinator.next_send_id += 1;
}

// Receive a message from a processor via its coordinator
async fn recv_message(coordinator: &mut Coordinator, from: NetworkId) -> ProcessorMessage {
  let msg = tokio::time::timeout(
    core::time::Duration::from_secs(10),
    coordinator.queue.next(coordinator.next_recv_id),
  )
  .await
  .unwrap();
  assert_eq!(msg.from, Service::Processor(from));
  assert_eq!(msg.id, coordinator.next_recv_id);
  coordinator.queue.ack(coordinator.next_recv_id).await;
  coordinator.next_recv_id += 1;
  serde_json::from_slice(&msg.msg).unwrap()
}

async fn key_gen(coordinators: &mut [Coordinator], network: NetworkId) {
  // Perform an interaction with all processors via their coordinators
  async fn interact_with_all<
    FS: Fn(Participant) -> messages::key_gen::CoordinatorMessage,
    FR: FnMut(Participant, messages::key_gen::ProcessorMessage),
  >(
    coordinators: &mut [Coordinator],
    network: NetworkId,
    message: FS,
    mut recv: FR,
  ) {
    for (i, coordinator) in coordinators.iter_mut().enumerate() {
      let participant = Participant::new(u16::try_from(i + 1).unwrap()).unwrap();
      send_message(coordinator, network, CoordinatorMessage::KeyGen(message(participant))).await;

      match recv_message(coordinator, network).await {
        ProcessorMessage::KeyGen(msg) => recv(participant, msg),
        _ => panic!("processor didn't return KeyGen message"),
      }
    }
  }

  // Order a key gen
  let id = KeyGenId { set: ValidatorSet { session: Session(0), network }, attempt: 0 };

  let mut commitments = HashMap::new();
  interact_with_all(
    coordinators,
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
    coordinators,
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
    coordinators,
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

  // Confirm the key pair
  // TODO: Beter document coin_latest_finalized_block's genesis state, and error if a set claims
  // [0; 32] was finalized
  let context = SubstrateContext {
    serai_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
    coin_latest_finalized_block: BlockHash([0; 32]),
  };
  for coordinator in coordinators {
    send_message(
      coordinator,
      network,
      CoordinatorMessage::Substrate(messages::substrate::CoordinatorMessage::ConfirmKeyPair {
        context,
        set: id.set,
        key_pair: (
          PublicKey::from_raw(substrate_key.unwrap()),
          coin_key.clone().unwrap().try_into().unwrap(),
        ),
      }),
    )
    .await;
  }
  tokio::time::sleep(core::time::Duration::from_secs(5)).await;
}

#[test]
fn key_gen_test() {
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
      let mut coordinators = coordinators
        .into_iter()
        .map(|(handle, key)| coordinator_queue(&ops, handle, key))
        .collect::<Vec<_>>();

      key_gen(&mut coordinators, network).await;
    });
  }
}
