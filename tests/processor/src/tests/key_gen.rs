use std::time::SystemTime;

use dkg::Participant;

use serai_client::{
  primitives::{NetworkId, BlockHash, PublicKey},
  validator_sets::primitives::{Session, KeyPair},
};

use messages::{SubstrateContext, CoordinatorMessage, ProcessorMessage};

use crate::{*, tests::*};

pub(crate) async fn key_gen(coordinators: &mut [Coordinator]) -> KeyPair {
  // Perform an interaction with all processors via their coordinators
  async fn interact_with_all<FR: FnMut(Participant, messages::key_gen::ProcessorMessage)>(
    coordinators: &mut [Coordinator],
    mut recv: FR,
  ) {
    for (i, coordinator) in coordinators.iter_mut().enumerate() {
      let participant = Participant::new(u16::try_from(i + 1).unwrap()).unwrap();
      match coordinator.recv_message().await {
        ProcessorMessage::KeyGen(msg) => recv(participant, msg),
        _ => panic!("processor didn't return KeyGen message"),
      }
    }
  }

  // Order a key gen
  let session = Session(0);

  let mut evrf_public_keys = vec![];
  for coordinator in &*coordinators {
    let keys = coordinator.evrf_keys();
    evrf_public_keys.push((keys.substrate, keys.network));
  }

  let mut participations = vec![];
  for coordinator in &mut *coordinators {
    coordinator
      .send_message(CoordinatorMessage::KeyGen(
        messages::key_gen::CoordinatorMessage::GenerateKey {
          session,
          threshold: u16::try_from(THRESHOLD).unwrap(),
          evrf_public_keys: evrf_public_keys.clone(),
        },
      ))
      .await;
  }
  // This takes forever on debug, as we use in these tests
  let ci_scaling_factor =
    1 + u64::from(u8::from(std::env::var("GITHUB_CI") == Ok("true".to_string())));
  tokio::time::sleep(core::time::Duration::from_secs(600 * ci_scaling_factor)).await;
  interact_with_all(coordinators, |participant, msg| match msg {
    messages::key_gen::ProcessorMessage::Participation { session: this_session, participation } => {
      assert_eq!(this_session, session);
      participations.push(messages::key_gen::CoordinatorMessage::Participation {
        session,
        participant,
        participation,
      });
    }
    _ => panic!("processor didn't return Participation in response to GenerateKey"),
  })
  .await;

  // Send the participations
  let mut substrate_key = None;
  let mut network_key = None;
  for participation in participations {
    for coordinator in &mut *coordinators {
      coordinator.send_message(participation.clone()).await;
    }
  }
  // This also takes a while on debug
  tokio::time::sleep(core::time::Duration::from_secs(240 * ci_scaling_factor)).await;
  interact_with_all(coordinators, |_, msg| match msg {
    messages::key_gen::ProcessorMessage::GeneratedKeyPair {
      session: this_session,
      substrate_key: this_substrate_key,
      network_key: this_network_key,
    } => {
      assert_eq!(this_session, session);
      if substrate_key.is_none() {
        substrate_key = Some(this_substrate_key);
        network_key = Some(this_network_key.clone());
      }
      assert_eq!(substrate_key.unwrap(), this_substrate_key);
      assert_eq!(network_key.as_ref().unwrap(), &this_network_key);
    }
    _ => panic!("processor didn't return GeneratedKeyPair in response to all Participations"),
  })
  .await;

  // Confirm the key pair
  // TODO: Better document network_latest_finalized_block's genesis state, and error if a set claims
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
          session,
          key_pair: key_pair.clone(),
        },
      ))
      .await;
  }

  key_pair
}

#[test]
fn key_gen_test() {
  for network in [NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero] {
    let (coordinators, test) = new_test(network);

    test.run(|ops| async move {
      // Sleep for a second for the message-queue to boot
      // It isn't an error to start immediately, it just silences an error
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;

      // Connect to the Message Queues as the coordinator
      let mut coordinators = coordinators
        .into_iter()
        .map(|(handles, key)| Coordinator::new(network, &ops, handles, key))
        .collect::<Vec<_>>();

      key_gen(&mut coordinators).await;
    });
  }
}
