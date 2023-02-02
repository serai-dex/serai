use std::collections::HashMap;

use frost::{curve::Ciphersuite, ThresholdParams, tests::clone_without};

use validator_sets_primitives::{Session, ValidatorSetIndex, ValidatorSetInstance};

use messages::key_gen::*;
use crate::{key_gen::KeyGen, tests::util::db::MemDb};

const ID: KeyGenId = KeyGenId {
  set: ValidatorSetInstance { session: Session(1), index: ValidatorSetIndex(2) },
  attempt: 3,
};

pub async fn test_key_gen<C: 'static + Ciphersuite>() {
  let mut key_gens = HashMap::new();
  for i in 1 ..= 3 {
    key_gens.insert(i, KeyGen::<C, _>::new(MemDb::new()));
  }

  let mut all_commitments = HashMap::new();
  for i in 1 ..= 3 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    key_gen
      .coordinator
      .send(CoordinatorMessage::KeyGen {
        id: ID,
        params: ThresholdParams::new(2, 3, u16::try_from(i).unwrap()).unwrap(),
      })
      .unwrap();
    if let Some(ProcessorMessage::KeyGenCommitments { id, commitments }) =
      key_gen.processor.recv().await
    {
      assert_eq!(id, ID);
      all_commitments.insert(u16::try_from(i).unwrap(), commitments);
    } else {
      panic!("didn't get commitments back");
    }
  }

  let mut all_shares = HashMap::new();
  for i in 1 ..= 3 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let i = u16::try_from(i).unwrap();
    key_gen
      .coordinator
      .send(CoordinatorMessage::KeyGenCommitments {
        id: ID,
        commitments: clone_without(&all_commitments, &i),
      })
      .unwrap();
    if let Some(ProcessorMessage::KeyGenShares { id, shares }) = key_gen.processor.recv().await {
      assert_eq!(id, ID);
      all_shares.insert(i, shares);
    } else {
      panic!("didn't get shares back");
    }
  }

  let mut res = None;
  for i in 1 ..= 3 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let i = u16::try_from(i).unwrap();
    key_gen
      .coordinator
      .send(CoordinatorMessage::KeyGenShares {
        id: ID,
        shares: all_shares
          .iter()
          .filter_map(|(l, shares)| if i == *l { None } else { Some((*l, shares[&i].clone())) })
          .collect(),
      })
      .unwrap();
    if let Some(ProcessorMessage::KeyGenCompletion { id, key }) = key_gen.processor.recv().await {
      assert_eq!(id, ID);
      if res.is_none() {
        res = Some(key.clone());
      }
      assert_eq!(res.as_ref().unwrap(), &key);
    } else {
      panic!("didn't get key back");
    }
  }
}
