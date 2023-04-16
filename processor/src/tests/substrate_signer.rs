use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use group::GroupEncoding;
use frost::{
  curve::Ristretto,
  Participant,
  dkg::tests::{key_gen, clone_without},
};

use scale::Encode;
use sp_application_crypto::{RuntimePublic, sr25519::Public};

use serai_db::MemDb;

use serai_client::{primitives::*, in_instructions::primitives::*};

use messages::{sign::SignId, coordinator::*};
use crate::substrate_signer::{SubstrateSignerEvent, SubstrateSigner};

#[tokio::test]
async fn test_substrate_signer() {
  let mut keys = key_gen::<_, Ristretto>(&mut OsRng);

  let participant_one = Participant::new(1).unwrap();

  let block = BlockHash([0xaa; 32]);
  let actual_id =
    SignId { key: keys[&participant_one].group_key().to_bytes().to_vec(), id: block.0, attempt: 0 };

  let batch = Batch {
    network: MONERO_NET_ID,
    id: 5,
    block,
    instructions: vec![
      InInstructionWithBalance {
        instruction: InInstruction::Transfer(SeraiAddress([0xbb; 32])),
        balance: Balance { coin: BITCOIN, amount: Amount(1000) },
      },
      InInstructionWithBalance {
        instruction: InInstruction::Call(ApplicationCall {
          application: Application::DEX,
          data: Data::new(vec![0xcc; 128]).unwrap(),
        }),
        balance: Balance { coin: MONERO, amount: Amount(9999999999999999) },
      },
    ],
  };

  let mut signers = HashMap::new();
  let mut t = 0;
  for i in 1 ..= keys.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let keys = keys.remove(&i).unwrap();
    t = keys.params().t();
    let mut signer = SubstrateSigner::new(MemDb::new(), keys);
    signer.sign(batch.clone()).await;
    signers.insert(i, signer);
  }
  drop(keys);

  let mut signing_set = vec![];
  while signing_set.len() < usize::from(t) {
    let candidate = Participant::new(
      u16::try_from((OsRng.next_u64() % u64::try_from(signers.len()).unwrap()) + 1).unwrap(),
    )
    .unwrap();
    if signing_set.contains(&candidate) {
      continue;
    }
    signing_set.push(candidate);
  }

  // All participants should emit a preprocess
  let mut preprocesses = HashMap::new();
  for i in 1 ..= signers.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let SubstrateSignerEvent::ProcessorMessage(ProcessorMessage::BatchPreprocess {
      id,
      preprocess,
    }) = signers.get_mut(&i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(id, actual_id);
      if signing_set.contains(&i) {
        preprocesses.insert(i, preprocess);
      }
    } else {
      panic!("didn't get preprocess back");
    }
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    signers
      .get_mut(i)
      .unwrap()
      .handle(CoordinatorMessage::BatchPreprocesses {
        id: actual_id.clone(),
        preprocesses: clone_without(&preprocesses, i),
      })
      .await;
    if let SubstrateSignerEvent::ProcessorMessage(ProcessorMessage::BatchShare { id, share }) =
      signers.get_mut(i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(id, actual_id);
      shares.insert(*i, share);
    } else {
      panic!("didn't get share back");
    }
  }

  for i in &signing_set {
    signers
      .get_mut(i)
      .unwrap()
      .handle(CoordinatorMessage::BatchShares {
        id: actual_id.clone(),
        shares: clone_without(&shares, i),
      })
      .await;

    if let SubstrateSignerEvent::SignedBatch(signed_batch) =
      signers.get_mut(i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(signed_batch.batch, batch);
      assert!(Public::from_raw(actual_id.key.clone().try_into().unwrap())
        .verify(&batch.encode(), &signed_batch.signature));
    } else {
      panic!("didn't get signed batch back");
    }
  }

  // Make sure there's no events left
  for (_, mut signer) in signers.drain() {
    assert!(signer.events.pop_front().is_none());
  }
}
