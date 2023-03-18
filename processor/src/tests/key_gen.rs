use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::{RngCore, OsRng};

use group::GroupEncoding;
use frost::{Participant, ThresholdParams, tests::clone_without};

use serai_client::validator_sets::primitives::{Session, ValidatorSetIndex, ValidatorSetInstance};

use messages::{SubstrateContext, key_gen::*};
use crate::{
  coins::Coin,
  key_gen::{KeyGenEvent, KeyGen},
  tests::util::db::MemDb,
};

const ID: KeyGenId = KeyGenId {
  set: ValidatorSetInstance { session: Session(1), index: ValidatorSetIndex(2) },
  attempt: 3,
};

pub async fn test_key_gen<C: Coin>() {
  let mut entropies = HashMap::new();
  let mut dbs = HashMap::new();
  let mut key_gens = HashMap::new();
  for i in 1 ..= 5 {
    let mut entropy = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(entropy.as_mut());
    entropies.insert(i, entropy);
    dbs.insert(i, MemDb::new());
    key_gens.insert(i, KeyGen::<C, _>::new(dbs[&i].clone(), entropies[&i].clone()));
  }

  let mut all_commitments = HashMap::new();
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    if let KeyGenEvent::ProcessorMessage(ProcessorMessage::Commitments { id, commitments }) =
      key_gen
        .handle(CoordinatorMessage::GenerateKey {
          id: ID,
          params: ThresholdParams::new(3, 5, Participant::new(u16::try_from(i).unwrap()).unwrap())
            .unwrap(),
        })
        .await
    {
      assert_eq!(id, ID);
      all_commitments.insert(Participant::new(u16::try_from(i).unwrap()).unwrap(), commitments);
    } else {
      panic!("didn't get commitments back");
    }
  }

  // 1 is rebuilt on every step
  // 2 is rebuilt here
  // 3 ... are rebuilt once, one at each of the following steps
  let rebuild = |key_gens: &mut HashMap<_, _>, i| {
    key_gens.remove(&i);
    key_gens.insert(i, KeyGen::<C, _>::new(dbs[&i].clone(), entropies[&i].clone()));
  };
  rebuild(&mut key_gens, 1);
  rebuild(&mut key_gens, 2);

  let mut all_shares = HashMap::new();
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let KeyGenEvent::ProcessorMessage(ProcessorMessage::Shares { id, shares }) = key_gen
      .handle(CoordinatorMessage::Commitments {
        id: ID,
        commitments: clone_without(&all_commitments, &i),
      })
      .await
    {
      assert_eq!(id, ID);
      all_shares.insert(i, shares);
    } else {
      panic!("didn't get shares back");
    }
  }

  // Rebuild 1 and 3
  rebuild(&mut key_gens, 1);
  rebuild(&mut key_gens, 3);

  let mut res = None;
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let KeyGenEvent::ProcessorMessage(ProcessorMessage::GeneratedKey { id, key }) = key_gen
      .handle(CoordinatorMessage::Shares {
        id: ID,
        shares: all_shares
          .iter()
          .filter_map(|(l, shares)| if i == *l { None } else { Some((*l, shares[&i].clone())) })
          .collect(),
      })
      .await
    {
      assert_eq!(id, ID);
      if res.is_none() {
        res = Some(key.clone());
      }
      assert_eq!(res.as_ref().unwrap(), &key);
    } else {
      panic!("didn't get key back");
    }
  }

  // Rebuild 1 and 4
  rebuild(&mut key_gens, 1);
  rebuild(&mut key_gens, 4);

  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    if let KeyGenEvent::KeyConfirmed { activation_number, keys } = key_gen
      .handle(CoordinatorMessage::ConfirmKey {
        context: SubstrateContext { time: 0, coin_latest_block_number: 111 },
        id: ID,
      })
      .await
    {
      assert_eq!(activation_number, 111);
      assert_eq!(
        keys.params(),
        ThresholdParams::new(3, 5, Participant::new(u16::try_from(i).unwrap()).unwrap()).unwrap()
      );
      assert_eq!(keys.group_key().to_bytes().as_ref(), res.as_ref().unwrap());
    } else {
      panic!("didn't get key back");
    }
  }
}
