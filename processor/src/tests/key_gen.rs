use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::{RngCore, OsRng};

use group::GroupEncoding;
use frost::{curve::Ciphersuite, ThresholdParams, tests::clone_without};

use serai_client::validator_sets::primitives::{Session, ValidatorSetIndex, ValidatorSetInstance};

use messages::{SubstrateContext, key_gen::*};
use crate::{
  key_gen::{KeyGenOrder, KeyGenEvent, KeyGen},
  tests::util::db::MemDb,
};

const ID: KeyGenId = KeyGenId {
  set: ValidatorSetInstance { session: Session(1), index: ValidatorSetIndex(2) },
  attempt: 3,
};

// TODO: Also test destroying and rebuilding KeyGen machines
pub async fn test_key_gen<C: 'static + Send + Ciphersuite>() {
  let mut key_gens = HashMap::new();
  for i in 1 ..= 3 {
    let mut entropy = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(entropy.as_mut());
    key_gens.insert(i, KeyGen::<C, _>::new(MemDb::new(), entropy));
  }

  let mut all_commitments = HashMap::new();
  for i in 1 ..= 3 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    key_gen
      .orders
      .send(KeyGenOrder::CoordinatorMessage(CoordinatorMessage::GenerateKey {
        id: ID,
        params: ThresholdParams::new(2, 3, u16::try_from(i).unwrap()).unwrap(),
      }))
      .unwrap();
    if let Some(KeyGenEvent::ProcessorMessage(ProcessorMessage::Commitments { id, commitments })) =
      key_gen.events.recv().await
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
      .orders
      .send(KeyGenOrder::CoordinatorMessage(CoordinatorMessage::Commitments {
        id: ID,
        commitments: clone_without(&all_commitments, &i),
      }))
      .unwrap();
    if let Some(KeyGenEvent::ProcessorMessage(ProcessorMessage::Shares { id, shares })) =
      key_gen.events.recv().await
    {
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
      .orders
      .send(KeyGenOrder::CoordinatorMessage(CoordinatorMessage::Shares {
        id: ID,
        shares: all_shares
          .iter()
          .filter_map(|(l, shares)| if i == *l { None } else { Some((*l, shares[&i].clone())) })
          .collect(),
      }))
      .unwrap();
    if let Some(KeyGenEvent::ProcessorMessage(ProcessorMessage::GeneratedKey { id, key })) =
      key_gen.events.recv().await
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

  for i in 1 ..= 3 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    key_gen
      .orders
      .send(KeyGenOrder::CoordinatorMessage(CoordinatorMessage::ConfirmKey {
        context: SubstrateContext { time: 0, coin_latest_block_number: 111 },
        id: ID,
      }))
      .unwrap();

    if let Some(KeyGenEvent::KeyConfirmed { activation_number, keys }) = key_gen.events.recv().await
    {
      assert_eq!(activation_number, 111);
      assert_eq!(keys.params(), ThresholdParams::new(2, 3, u16::try_from(i).unwrap()).unwrap());
      assert_eq!(keys.group_key().to_bytes().as_ref(), res.as_ref().unwrap());
    } else {
      panic!("didn't get key back");
    }
  }
  tokio::time::sleep(Duration::from_secs(1)).await;
}
