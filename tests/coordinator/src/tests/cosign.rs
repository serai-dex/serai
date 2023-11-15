use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use dkg::Participant;

use serai_client::primitives::Signature;
use messages::{
  coordinator::{SubstrateSignableId, cosign_block_msg},
  CoordinatorMessage,
};

use crate::{*, tests::*};

pub async fn potentially_cosign(
  processors: &mut [Processor],
  primary_processor: usize,
  processor_is: &[u8],
  substrate_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
) -> CoordinatorMessage {
  let msg = processors[primary_processor].recv_message().await;
  let messages::CoordinatorMessage::Coordinator(
    messages::coordinator::CoordinatorMessage::CosignSubstrateBlock { id },
  ) = msg.clone()
  else {
    return msg;
  };
  let SubstrateSignableId::CosigningSubstrateBlock(block) = id.id else {
    panic!("CosignSubstrateBlock didn't have CosigningSubstrateBlock id")
  };

  for (i, processor) in processors.iter_mut().enumerate() {
    if i == primary_processor {
      continue;
    }
    assert_eq!(msg, processor.recv_message().await);
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
      .send_message(messages::coordinator::ProcessorMessage::CosignPreprocess {
        id: id.clone(),
        preprocesses: vec![[processor_is[i]; 64].to_vec()],
      })
      .await;
  }

  // Send from the excluded signer so they don't stay stuck
  processors[excluded_signer]
    .send_message(messages::coordinator::ProcessorMessage::CosignPreprocess {
      id: id.clone(),
      preprocesses: vec![[processor_is[excluded_signer]; 64].to_vec()],
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

      let mut participants = preprocesses.keys().cloned().collect::<HashSet<_>>();
      for (p, preprocess) in preprocesses {
        assert_eq!(preprocess, vec![u8::try_from(u16::from(p)).unwrap(); 64]);
      }
      participants.insert(known_signer_i);
      participants
    }
    _ => panic!("coordinator didn't send back SubstratePreprocesses"),
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
      .map(|i| (i, [u8::try_from(u16::from(i)).unwrap(); 64].to_vec()))
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
      .sign_simple(b"substrate", &cosign_block_msg(block))
      .to_bytes(),
  );

  for (i, processor) in processors.iter_mut().enumerate() {
    if i == excluded_signer {
      continue;
    }
    processor
      .send_message(messages::coordinator::ProcessorMessage::CosignedBlock {
        block,
        signature: signature.0.to_vec(),
      })
      .await;
  }

  processors[primary_processor].recv_message().await
}
