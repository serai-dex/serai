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

#[rustfmt::skip]
use serai_client::{primitives::*, in_instructions::primitives::*, validator_sets::primitives::Session};

use messages::{
  substrate,
  coordinator::{self, SubstrateSignableId, SubstrateSignId, CoordinatorMessage},
  ProcessorMessage,
};
use crate::batch_signer::BatchSigner;

#[test]
fn test_batch_signer() {
  let keys = key_gen::<_, Ristretto>(&mut OsRng);

  let participant_one = Participant::new(1).unwrap();

  let id: u32 = 5;
  let block = BlockHash([0xaa; 32]);

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
        instruction: InInstruction::Dex(DexCall::SwapAndAddLiquidity(SeraiAddress([0xbb; 32]))),
        balance: Balance { coin: Coin::Monero, amount: Amount(9999999999999999) },
      },
    ],
  };

  let actual_id =
    SubstrateSignId { session: Session(0), id: SubstrateSignableId::Batch(batch.id), attempt: 0 };

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

    let mut signer = BatchSigner::<MemDb>::new(NetworkId::Monero, Session(0), vec![keys]);
    let mut db = MemDb::new();

    let mut txn = db.txn();
    match signer.sign(&mut txn, batch.clone()).unwrap() {
      // All participants should emit a preprocess
      coordinator::ProcessorMessage::BatchPreprocess {
        id,
        block: batch_block,
        preprocesses: mut these_preprocesses,
      } => {
        assert_eq!(id, actual_id);
        assert_eq!(batch_block, block);
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
      ProcessorMessage::Coordinator(coordinator::ProcessorMessage::SubstrateShare {
        id,
        shares: mut these_shares,
      }) => {
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
      ProcessorMessage::Substrate(substrate::ProcessorMessage::SignedBatch {
        batch: signed_batch,
      }) => {
        assert_eq!(signed_batch.batch, batch);
        assert!(Public::from_raw(keys[&participant_one].group_key().to_bytes())
          .verify(&batch_message(&batch), &signed_batch.signature));
      }
      _ => panic!("didn't get signed batch back"),
    }
    txn.commit();
  }
}
