use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use ciphersuite::group::GroupEncoding;
use frost::{
  curve::Ristretto,
  Participant,
  dkg::tests::{key_gen, clone_without},
};

use sp_application_crypto::{RuntimePublic, sr25519::Public};

use serai_db::{DbTxn, Db, MemDb};

use serai_client::{primitives::*, in_instructions::primitives::*};

use messages::{sign::SignId, coordinator::*};
use crate::substrate_signer::{SubstrateSignerEvent, SubstrateSigner};

#[tokio::test]
async fn test_substrate_signer() {
  let mut keys = key_gen::<_, Ristretto>(&mut OsRng);

  let participant_one = Participant::new(1).unwrap();

  let id: u32 = 5;
  let mut id_slice = [0u8; 32];
  id_slice[.. 4].copy_from_slice(&id.to_le_bytes());
  let block = BlockHash([0xaa; 32]);
  let actual_id = SignId {
    key: keys[&participant_one].group_key().to_bytes().to_vec(),
    id: id_slice,
    attempt: 0,
  };

  let batch = Batch {
    network: NetworkId::Monero,
    id,
    block,
    instructions: vec![
      InInstructionWithBalance {
        instruction: InInstruction::Transfer(SeraiAddress([0xbb; 32])),
        balance: Balance { coin: Coin::Bitcoin, amount: Amount(1000) },
      },
      InInstructionWithBalance {
        instruction: InInstruction::Dex(Data::new(vec![0xcc; 128]).unwrap()),
        balance: Balance { coin: Coin::Monero, amount: Amount(9999999999999999) },
      },
    ],
  };

  let mut signers = HashMap::new();
  let mut dbs = HashMap::new();
  let mut t = 0;
  for i in 1 ..= keys.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let keys = keys.remove(&i).unwrap();
    t = keys.params().t();

    let mut signer = SubstrateSigner::<MemDb>::new(keys);
    let mut db = MemDb::new();
    let mut txn = db.txn();
    signer.sign(&mut txn, batch.clone()).await;
    txn.commit();

    signers.insert(i, signer);
    dbs.insert(i, db);
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
      block: batch_block,
      preprocess,
    }) = signers.get_mut(&i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(id, actual_id);
      assert_eq!(batch_block, block);
      if signing_set.contains(&i) {
        preprocesses.insert(i, preprocess);
      }
    } else {
      panic!("didn't get preprocess back");
    }
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::BatchPreprocesses {
          id: actual_id.clone(),
          preprocesses: clone_without(&preprocesses, i),
        },
      )
      .await;
    txn.commit();

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
    let mut txn = dbs.get_mut(i).unwrap().txn();
    signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::BatchShares {
          id: actual_id.clone(),
          shares: clone_without(&shares, i),
        },
      )
      .await;
    txn.commit();

    if let SubstrateSignerEvent::SignedBatch(signed_batch) =
      signers.get_mut(i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(signed_batch.batch, batch);
      assert!(Public::from_raw(actual_id.key.clone().try_into().unwrap())
        .verify(&batch_message(&batch), &signed_batch.signature));
    } else {
      panic!("didn't get signed batch back");
    }
  }

  // Make sure there's no events left
  for (_, mut signer) in signers.drain() {
    assert!(signer.events.pop_front().is_none());
  }
}
