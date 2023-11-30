use std::{collections::HashMap, time::SystemTime};

use dkg::{Participant, ThresholdParams, tests::clone_without};

use serai_client::{
  primitives::{NetworkId, BlockHash, PublicKey},
  validator_sets::primitives::{Session, KeyPair},
};

use messages::{SubstrateContext, key_gen::KeyGenId, CoordinatorMessage, ProcessorMessage};

use crate::{*, tests::*};

pub(crate) async fn key_gen(coordinators: &mut [Coordinator]) -> KeyPair {
  // Perform an interaction with all processors via their coordinators
  async fn interact_with_all<
    FS: Fn(Participant) -> messages::key_gen::CoordinatorMessage,
    FR: FnMut(Participant, messages::key_gen::ProcessorMessage),
  >(
    coordinators: &mut [Coordinator],
    message: FS,
    mut recv: FR,
  ) {
    for (i, coordinator) in coordinators.iter_mut().enumerate() {
      let participant = Participant::new(u16::try_from(i + 1).unwrap()).unwrap();
      coordinator.send_message(CoordinatorMessage::KeyGen(message(participant))).await;

      match coordinator.recv_message().await {
        ProcessorMessage::KeyGen(msg) => recv(participant, msg),
        _ => panic!("processor didn't return KeyGen message"),
      }
    }
  }

  // Order a key gen
  let id = KeyGenId { session: Session(0), attempt: 0 };

  let mut commitments = HashMap::new();
  interact_with_all(
    coordinators,
    |participant| messages::key_gen::CoordinatorMessage::GenerateKey {
      id,
      params: ThresholdParams::new(
        u16::try_from(THRESHOLD).unwrap(),
        u16::try_from(COORDINATORS).unwrap(),
        participant,
      )
      .unwrap(),
      shares: 1,
    },
    |participant, msg| match msg {
      messages::key_gen::ProcessorMessage::Commitments {
        id: this_id,
        commitments: mut these_commitments,
      } => {
        assert_eq!(this_id, id);
        assert_eq!(these_commitments.len(), 1);
        commitments.insert(participant, these_commitments.swap_remove(0));
      }
      _ => panic!("processor didn't return Commitments in response to GenerateKey"),
    },
  )
  .await;

  // Send the commitments to all parties
  let mut shares = HashMap::new();
  interact_with_all(
    coordinators,
    |participant| messages::key_gen::CoordinatorMessage::Commitments {
      id,
      commitments: clone_without(&commitments, &participant),
    },
    |participant, msg| match msg {
      messages::key_gen::ProcessorMessage::Shares { id: this_id, shares: mut these_shares } => {
        assert_eq!(this_id, id);
        assert_eq!(these_shares.len(), 1);
        shares.insert(participant, these_shares.swap_remove(0));
      }
      _ => panic!("processor didn't return Shares in response to GenerateKey"),
    },
  )
  .await;

  // Send the shares
  let mut substrate_key = None;
  let mut network_key = None;
  interact_with_all(
    coordinators,
    |participant| messages::key_gen::CoordinatorMessage::Shares {
      id,
      shares: vec![shares
        .iter()
        .filter_map(|(this_participant, shares)| {
          shares.get(&participant).cloned().map(|share| (*this_participant, share))
        })
        .collect()],
    },
    |_, msg| match msg {
      messages::key_gen::ProcessorMessage::GeneratedKeyPair {
        id: this_id,
        substrate_key: this_substrate_key,
        network_key: this_network_key,
      } => {
        assert_eq!(this_id, id);
        if substrate_key.is_none() {
          substrate_key = Some(this_substrate_key);
          network_key = Some(this_network_key.clone());
        }
        assert_eq!(substrate_key.unwrap(), this_substrate_key);
        assert_eq!(network_key.as_ref().unwrap(), &this_network_key);
      }
      _ => panic!("processor didn't return GeneratedKeyPair in response to GenerateKey"),
    },
  )
  .await;

  // Confirm the key pair
  // TODO: Beter document network_latest_finalized_block's genesis state, and error if a set claims
  // [0; 32] was finalized
  let context = SubstrateContext {
    serai_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
    network_latest_finalized_block: BlockHash([0; 32]),
  };

  let key_pair = KeyPair(
    PublicKey::from_raw(substrate_key.unwrap()),
    network_key.clone().unwrap().try_into().unwrap(),
  );

  for coordinator in coordinators {
    coordinator
      .send_message(CoordinatorMessage::Substrate(
        messages::substrate::CoordinatorMessage::ConfirmKeyPair {
          context,
          session: id.session,
          key_pair: key_pair.clone(),
        },
      ))
      .await;
  }

  key_pair
}

#[tokio::test]
async fn key_gen_test() {
  for network in [NetworkId::Bitcoin, NetworkId::Monero] {
    let (coordinators, test) = new_test(network).await;

    test
      .run_async(|ops| async move {
        // Sleep for a second for the message-queue to boot
        // It isn't an error to start immediately, it just silences an error
        tokio::time::sleep(core::time::Duration::from_secs(1)).await;

        // Connect to the Message Queues as the coordinator
        let mut coordinators = coordinators
          .into_iter()
          .map(|(handles, key)| Coordinator::new(network, &ops, handles, key))
          .collect::<Vec<_>>();

        key_gen(&mut coordinators).await;
      })
      .await;
  }
}
