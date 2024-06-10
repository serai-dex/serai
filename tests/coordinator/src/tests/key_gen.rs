use std::{
  time::{Duration, SystemTime},
  collections::HashMap,
};

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto, Secp256k1,
};
use dkg::ThresholdParams;

use serai_client::{
  primitives::NetworkId,
  Public,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
};
use messages::{key_gen::KeyGenId, CoordinatorMessage};

use crate::tests::*;

pub async fn key_gen<C: Ciphersuite>(
  processors: &mut [Processor],
  session: Session,
) -> (Vec<u8>, Zeroizing<<Ristretto as Ciphersuite>::F>, Zeroizing<C::F>) {
  let coordinators = processors.len();
  let mut participant_is = vec![];

  let set = ValidatorSet { session, network: NetworkId::Bitcoin };
  let id = KeyGenId { session: set.session, attempt: 0 };

  for (i, processor) in processors.iter_mut().enumerate() {
    let msg = processor.recv_message().await;
    match &msg {
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
        params,
        ..
      }) => {
        participant_is.push(params.i());
      }
      _ => panic!("unexpected message: {msg:?}"),
    }

    assert_eq!(
      msg,
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::GenerateKey {
        id,
        params: ThresholdParams::new(
          u16::try_from(((coordinators * 2) / 3) + 1).unwrap(),
          u16::try_from(coordinators).unwrap(),
          participant_is[i],
        )
        .unwrap(),
        shares: 1,
      })
    );

    processor
      .send_message(messages::key_gen::ProcessorMessage::Commitments {
        id,
        commitments: vec![vec![u8::try_from(u16::from(participant_is[i])).unwrap()]],
      })
      .await;
  }

  wait_for_tributary().await;
  for (i, processor) in processors.iter_mut().enumerate() {
    let mut commitments = (0 .. u8::try_from(coordinators).unwrap())
      .map(|l| {
        (
          participant_is[usize::from(l)],
          vec![u8::try_from(u16::from(participant_is[usize::from(l)])).unwrap()],
        )
      })
      .collect::<HashMap<_, _>>();
    commitments.remove(&participant_is[i]);
    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::Commitments {
        id,
        commitments,
      })
    );

    // Recipient it's for -> (Sender i, Recipient i)
    let mut shares = (0 .. u8::try_from(coordinators).unwrap())
      .map(|l| {
        (
          participant_is[usize::from(l)],
          vec![
            u8::try_from(u16::from(participant_is[i])).unwrap(),
            u8::try_from(u16::from(participant_is[usize::from(l)])).unwrap(),
          ],
        )
      })
      .collect::<HashMap<_, _>>();

    shares.remove(&participant_is[i]);
    processor
      .send_message(messages::key_gen::ProcessorMessage::Shares { id, shares: vec![shares] })
      .await;
  }

  let substrate_priv_key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let substrate_key = (<Ristretto as Ciphersuite>::generator() * *substrate_priv_key).to_bytes();

  let network_priv_key = Zeroizing::new(C::F::random(&mut OsRng));
  let network_key = (C::generator() * *network_priv_key).to_bytes().as_ref().to_vec();

  let serai = processors[0].serai().await;
  let mut last_serai_block = serai.latest_finalized_block().await.unwrap().number();

  wait_for_tributary().await;
  for (i, processor) in processors.iter_mut().enumerate() {
    let i = participant_is[i];
    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::KeyGen(messages::key_gen::CoordinatorMessage::Shares {
        id,
        shares: {
          let mut shares = (0 .. u8::try_from(coordinators).unwrap())
            .map(|l| {
              (
                participant_is[usize::from(l)],
                vec![
                  u8::try_from(u16::from(participant_is[usize::from(l)])).unwrap(),
                  u8::try_from(u16::from(i)).unwrap(),
                ],
              )
            })
            .collect::<HashMap<_, _>>();
          shares.remove(&i);
          vec![shares]
        },
      })
    );
    processor
      .send_message(messages::key_gen::ProcessorMessage::GeneratedKeyPair {
        id,
        substrate_key,
        network_key: network_key.clone(),
      })
      .await;
  }

  // Sleeps for longer since we need to wait for a Substrate block as well
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
