use std::{
  time::Duration,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};
use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto, Secp256k1};
use dkg::Participant;

use scale::Encode;

use serai_client::{
  primitives::{NetworkId, BlockHash, Signature},
  in_instructions::{
    primitives::{Batch, SignedBatch, batch_message},
    InInstructionsEvent,
  },
  validator_sets::primitives::Session,
};
use messages::{
  coordinator::{SubstrateSignableId, SubstrateSignId},
  SubstrateContext, CoordinatorMessage,
};

use crate::{*, tests::*};

pub async fn batch(
  processors: &mut [Processor],
  processor_is: &[u8],
  session: Session,
  substrate_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  batch: Batch,
) -> u64 {
  let id = SubstrateSignId { session, id: SubstrateSignableId::Batch(batch.id), attempt: 0 };

  for processor in &mut *processors {
    processor
      .send_message(messages::substrate::ProcessorMessage::Batch { batch: batch.clone() })
      .await;
  }

  // Select a random participant to exclude, so we know for sure who *is* participating
  assert_eq!(COORDINATORS - THRESHOLD, 1);
  let excluded_signer =
    usize::try_from(OsRng.next_u64() % u64::try_from(processors.len()).unwrap()).unwrap();
  for (i, processor) in processors.iter_mut().enumerate() {
    if i == excluded_signer {
      continue;
    }

    processor
      .send_message(messages::coordinator::ProcessorMessage::BatchPreprocess {
        id: id.clone(),
        block: batch.block,
        preprocesses: vec![[processor_is[i]; 64]],
      })
      .await;
  }
  // Before this Batch is signed, the Tributary will agree this block occurred, adding an extra
  // step of latency
  wait_for_tributary().await;
  wait_for_tributary().await;

  // Send from the excluded signer so they don't stay stuck
  processors[excluded_signer]
    .send_message(messages::coordinator::ProcessorMessage::BatchPreprocess {
      id: id.clone(),
      block: batch.block,
      preprocesses: vec![[processor_is[excluded_signer]; 64]],
    })
    .await;

  // Read from a known signer to find out who was selected to sign
  let known_signer = (excluded_signer + 1) % COORDINATORS;
  let first_preprocesses = processors[known_signer].recv_message().await;
  let participants = match first_preprocesses {
    CoordinatorMessage::Coordinator(
      messages::coordinator::CoordinatorMessage::SubstratePreprocesses {
        id: this_id,
        preprocesses,
      },
    ) => {
      assert_eq!(&id, &this_id);
      assert_eq!(preprocesses.len(), THRESHOLD - 1);
      let known_signer_i = Participant::new(u16::from(processor_is[known_signer])).unwrap();
      assert!(!preprocesses.contains_key(&known_signer_i));

      let mut participants = preprocesses.keys().copied().collect::<HashSet<_>>();
      for (p, preprocess) in preprocesses {
        assert_eq!(preprocess, [u8::try_from(u16::from(p)).unwrap(); 64]);
      }
      participants.insert(known_signer_i);
      participants
    }
    other => panic!("coordinator didn't send back SubstratePreprocesses: {other:?}"),
  };

  for i in participants.clone() {
    if u16::from(i) == u16::from(processor_is[known_signer]) {
      continue;
    }

    let processor =
      &mut processors[processor_is.iter().position(|p_i| u16::from(*p_i) == u16::from(i)).unwrap()];
    let mut preprocesses = participants
      .clone()
      .into_iter()
      .map(|i| (i, [u8::try_from(u16::from(i)).unwrap(); 64]))
      .collect::<HashMap<_, _>>();
    preprocesses.remove(&i);

    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::SubstratePreprocesses {
          id: id.clone(),
          preprocesses
        }
      )
    );
  }

  for i in participants.clone() {
    let processor =
      &mut processors[processor_is.iter().position(|p_i| u16::from(*p_i) == u16::from(i)).unwrap()];
    processor
      .send_message(messages::coordinator::ProcessorMessage::SubstrateShare {
        id: id.clone(),
        shares: vec![[u8::try_from(u16::from(i)).unwrap(); 32]],
      })
      .await;
  }
  wait_for_tributary().await;
  for i in participants.clone() {
    let processor =
      &mut processors[processor_is.iter().position(|p_i| u16::from(*p_i) == u16::from(i)).unwrap()];
    let mut shares = participants
      .clone()
      .into_iter()
      .map(|i| (i, [u8::try_from(u16::from(i)).unwrap(); 32]))
      .collect::<HashMap<_, _>>();
    shares.remove(&i);

    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::Coordinator(messages::coordinator::CoordinatorMessage::SubstrateShares {
        id: id.clone(),
        shares,
      })
    );
  }

  // Expand to a key pair as Schnorrkel expects
  // It's the private key + 32-bytes of entropy for nonces + the public key
  let mut schnorrkel_key_pair = [0; 96];
  schnorrkel_key_pair[.. 32].copy_from_slice(&substrate_key.to_repr());
  OsRng.fill_bytes(&mut schnorrkel_key_pair[32 .. 64]);
  schnorrkel_key_pair[64 ..]
    .copy_from_slice(&(<Ristretto as Ciphersuite>::generator() * **substrate_key).to_bytes());
  let signature = Signature(
    schnorrkel::keys::Keypair::from_bytes(&schnorrkel_key_pair)
      .unwrap()
      .sign_simple(b"substrate", &batch_message(&batch))
      .to_bytes(),
  );

  let batch = SignedBatch { batch, signature };

  let serai = processors[0].serai().await;
  let mut last_serai_block = serai.latest_finalized_block().await.unwrap().number();

  for (i, processor) in processors.iter_mut().enumerate() {
    if i == excluded_signer {
      continue;
    }
    processor
      .send_message(messages::substrate::ProcessorMessage::SignedBatch { batch: batch.clone() })
      .await;
  }

  // Verify the Batch was published to Substrate
  'outer: for _ in 0 .. 20 {
    tokio::time::sleep(Duration::from_secs(6)).await;
    if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }

    while last_serai_block <= serai.latest_finalized_block().await.unwrap().number() {
      let batch_events = serai
        .as_of(serai.finalized_block_by_number(last_serai_block).await.unwrap().unwrap().hash())
        .in_instructions()
        .batch_events()
        .await
        .unwrap();

      if !batch_events.is_empty() {
        assert_eq!(batch_events.len(), 1);
        assert_eq!(
          batch_events[0],
          InInstructionsEvent::Batch {
            network: batch.batch.network,
            id: batch.batch.id,
            block: batch.batch.block,
            instructions_hash: Blake2b::<U32>::digest(batch.batch.instructions.encode()).into(),
          }
        );
        break 'outer;
      }
      last_serai_block += 1;
    }
  }

  // Verify the coordinator sends SubstrateBlock to all processors
  let last_block = serai.finalized_block_by_number(last_serai_block).await.unwrap().unwrap();
  for processor in &mut *processors {
    // Handle a potential re-attempt message in the pipeline
    let mut received = processor.recv_message().await;
    if matches!(
      received,
      messages::CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::BatchReattempt { .. }
      )
    ) {
      received = processor.recv_message().await
    }

    assert_eq!(
      received,
      messages::CoordinatorMessage::Substrate(
        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context: SubstrateContext {
            serai_time: last_block.time().unwrap() / 1000,
            network_latest_finalized_block: batch.batch.block,
          },
          block: last_serai_block,
          burns: vec![],
          batches: vec![batch.batch.id],
        }
      )
    );

    // Send the ack as expected
    processor
      .send_message(messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::SubstrateBlockAck {
          block: last_serai_block,
          plans: vec![],
        },
      ))
      .await;
  }
  last_block.number()
}

#[tokio::test]
async fn batch_test() {
  new_test(
    |mut processors: Vec<Processor>| async move {
      // pop the last participant since genesis keygen has only 4 participants
      processors.pop().unwrap();
      assert_eq!(processors.len(), COORDINATORS);

      let (processor_is, substrate_key, _) =
        key_gen::<Secp256k1>(&mut processors, Session(0)).await;
      batch(
        &mut processors,
        &processor_is,
        Session(0),
        &substrate_key,
        Batch {
          network: NetworkId::Bitcoin,
          id: 0,
          block: BlockHash([0x22; 32]),
          instructions: vec![],
        },
      )
      .await;
    },
    false,
  )
  .await;
}
