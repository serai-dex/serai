// TODO

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

use serai_client::{primitives::*, validator_sets::primitives::Session};

use messages::coordinator::*;
use crate::cosigner::Cosigner;

#[test]
fn test_cosigner() {
  let keys = key_gen::<_, Ristretto>(&mut OsRng);

  let participant_one = Participant::new(1).unwrap();

  let block_number = OsRng.next_u64();
  let block = [0xaa; 32];

  let actual_id = SubstrateSignId {
    session: Session(0),
    id: SubstrateSignableId::CosigningSubstrateBlock(block),
    attempt: (OsRng.next_u64() >> 32).try_into().unwrap(),
  };

  let mut signing_set = vec![];
  while signing_set.len() < usize::from(keys.values().next().unwrap().params().t()) {
    let candidate = Participant::new(
      u16::try_from((OsRng.next_u64() % u64::try_from(keys.len()).unwrap()) + 1).unwrap(),
    )
    .unwrap();
    if signing_set.contains(&candidate) {
      continue;
    }
    signing_set.push(candidate);
  }

  let mut signers = HashMap::new();
  let mut dbs = HashMap::new();
  let mut preprocesses = HashMap::new();
  for i in 1 ..= keys.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let keys = keys.get(&i).unwrap().clone();

    let mut db = MemDb::new();
    let mut txn = db.txn();
    let (signer, preprocess) =
      Cosigner::new(&mut txn, Session(0), vec![keys], block_number, block, actual_id.attempt)
        .unwrap();

    match preprocess {
      // All participants should emit a preprocess
      ProcessorMessage::CosignPreprocess { id, preprocesses: mut these_preprocesses } => {
        assert_eq!(id, actual_id);
        assert_eq!(these_preprocesses.len(), 1);
        if signing_set.contains(&i) {
          preprocesses.insert(i, these_preprocesses.swap_remove(0));
        }
      }
      _ => panic!("didn't get preprocess back"),
    }
    txn.commit();

    signers.insert(i, signer);
    dbs.insert(i, db);
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    match signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::SubstratePreprocesses {
          id: actual_id.clone(),
          preprocesses: clone_without(&preprocesses, i),
        },
      )
      .unwrap()
    {
      ProcessorMessage::SubstrateShare { id, shares: mut these_shares } => {
        assert_eq!(id, actual_id);
        assert_eq!(these_shares.len(), 1);
        shares.insert(*i, these_shares.swap_remove(0));
      }
      _ => panic!("didn't get share back"),
    }
    txn.commit();
  }

  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    match signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::SubstrateShares {
          id: actual_id.clone(),
          shares: clone_without(&shares, i),
        },
      )
      .unwrap()
    {
      ProcessorMessage::CosignedBlock { block_number, block: signed_block, signature } => {
        assert_eq!(signed_block, block);
        assert!(Public::from_raw(keys[&participant_one].group_key().to_bytes()).verify(
          &cosign_block_msg(block_number, block),
          &Signature(signature.try_into().unwrap())
        ));
      }
      _ => panic!("didn't get cosigned block back"),
    }
    txn.commit();
  }
}
