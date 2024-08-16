use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto, Secp256k1,
};
use dkg::Participant;

use serai_client::{
  primitives::NetworkId,
  Public,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
};
use messages::CoordinatorMessage;

use crate::tests::*;

pub async fn key_gen<C: Ciphersuite>(
  processors: &mut [Processor],
  session: Session,
) -> (Vec<u8>, Zeroizing<<Ristretto as Ciphersuite>::F>, Zeroizing<C::F>) {
  let coordinators = processors.len();
  let mut participant_is = vec![];

  let set = ValidatorSet { session, network: NetworkId::Bitcoin };

  // This is distinct from the result of evrf_public_keys for each processor, as there'll have some
  // ordering algorithm on-chain which won't match our ordering
  let mut evrf_public_keys_as_on_chain = None;
  for processor in processors.iter_mut() {
    // Receive GenerateKey
    let msg = processor.recv_message().await;
    match &msg {
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
        evrf_public_keys,
        ..
      }) => {
        if evrf_public_keys_as_on_chain.is_none() {
          evrf_public_keys_as_on_chain = Some(evrf_public_keys.clone());
        }
        assert_eq!(evrf_public_keys_as_on_chain.as_ref().unwrap(), evrf_public_keys);
        let i = evrf_public_keys
          .iter()
          .position(|public_keys| *public_keys == processor.evrf_public_keys())
          .unwrap();
        let i = Participant::new(1 + u16::try_from(i).unwrap()).unwrap();
        participant_is.push(i);
      }
      _ => panic!("unexpected message: {msg:?}"),
    }

    assert_eq!(
      msg,
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
        session,
        threshold: u16::try_from(((coordinators * 2) / 3) + 1).unwrap(),
        evrf_public_keys: evrf_public_keys_as_on_chain.clone().unwrap(),
      })
    );
  }

  for i in 0 .. coordinators {
    // Send Participation
    processors[i]
      .send_message(messages::key_gen::ProcessorMessage::Participation {
        session,
        participation: vec![u8::try_from(u16::from(participant_is[i])).unwrap()],
      })
      .await;

    // Sleep so this participation gets included
    for _ in 0 .. 2 {
      wait_for_tributary().await;
    }

    // Have every other processor recv this message too
    for processor in processors.iter_mut() {
      assert_eq!(
        processor.recv_message().await,
        messages::CoordinatorMessage::KeyGen(
          messages::key_gen::CoordinatorMessage::Participation {
            session,
            participant: participant_is[i],
            participation: vec![u8::try_from(u16::from(participant_is[i])).unwrap()],
          }
        )
      );
    }
  }

  // Now that we've received all participations, publish the key pair
  let substrate_priv_key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let substrate_key = (<Ristretto as Ciphersuite>::generator() * *substrate_priv_key).to_bytes();

  let network_priv_key = Zeroizing::new(C::F::random(&mut OsRng));
  let network_key = (C::generator() * *network_priv_key).to_bytes().as_ref().to_vec();

  let serai = processors[0].serai().await;
  let mut last_serai_block = serai.latest_finalized_block().await.unwrap().number();

  for processor in processors.iter_mut() {
    processor
      .send_message(messages::key_gen::ProcessorMessage::GeneratedKeyPair {
        session,
        substrate_key,
        network_key: network_key.clone(),
      })
      .await;
  }

  // Wait for the Nonces TXs to go around
  wait_for_tributary().await;
  // Wait for the Share TXs to go around
  wait_for_tributary().await;

  // And now we're waiting ro the TX to be published onto Serai

  // We need to wait for a finalized Substrate block as well, so this waites for up to 20 blocks
  'outer: for _ in 0 .. 20 {
    tokio::time::sleep(Duration::from_secs(6)).await;
    if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }

    while last_serai_block <= serai.latest_finalized_block().await.unwrap().number() {
      if !serai
        .as_of(serai.finalized_block_by_number(last_serai_block).await.unwrap().unwrap().hash())
        .validator_sets()
        .key_gen_events()
        .await
        .unwrap()
        .is_empty()
      {
        break 'outer;
      }
      last_serai_block += 1;
    }
  }
  let mut message = None;
  for processor in &mut *processors {
    let msg = processor.recv_message().await;
    if message.is_none() {
      match msg {
        CoordinatorMessage::Substrate(
          messages::substrate::CoordinatorMessage::ConfirmKeyPair {
            context,
            session,
            ref key_pair,
          },
        ) => {
          assert!(
            SystemTime::now()
              .duration_since(SystemTime::UNIX_EPOCH)
              .unwrap()
              .as_secs()
              .abs_diff(context.serai_time) <
              (60 * 60 * 3) // 3 hours, which should exceed the length of any test we run
          );
          assert_eq!(context.network_latest_finalized_block.0, [0; 32]);
          assert_eq!(set.session, session);
          assert_eq!(key_pair.0 .0, substrate_key);
          assert_eq!(&key_pair.1, &network_key);
        }
        _ => panic!("coordinator didn't respond with ConfirmKeyPair. msg: {msg:?}"),
      }
      message = Some(msg);
    } else {
      assert_eq!(message, Some(msg));
    }
  }
  assert_eq!(
    serai
      .as_of(serai.finalized_block_by_number(last_serai_block).await.unwrap().unwrap().hash())
      .validator_sets()
      .keys(set)
      .await
      .unwrap()
      .unwrap(),
    KeyPair(Public(substrate_key), network_key.try_into().unwrap())
  );

  for processor in &mut *processors {
    processor.set_substrate_key(substrate_priv_key.clone()).await;
  }

  (
    participant_is.into_iter().map(|i| u8::try_from(u16::from(i)).unwrap()).collect(),
    substrate_priv_key,
    network_priv_key,
  )
}

#[tokio::test]
async fn key_gen_test() {
  new_test(
    |mut processors: Vec<Processor>| async move {
      // pop the last participant since genesis keygen has only 4 participants
      processors.pop().unwrap();
      assert_eq!(processors.len(), COORDINATORS);

      key_gen::<Secp256k1>(&mut processors, Session(0)).await;
    },
    false,
  )
  .await;
}
