use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::{RngCore, OsRng};

use ciphersuite::group::GroupEncoding;
use frost::{Participant, ThresholdParams, tests::clone_without};

use serai_db::{DbTxn, Db, MemDb};

use sp_application_crypto::sr25519;
use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
};

use messages::key_gen::*;
use crate::{
  networks::Network,
  key_gen::{KeyConfirmed, KeyGen},
};

const ID: KeyGenId =
  KeyGenId { set: ValidatorSet { session: Session(1), network: NetworkId::Monero }, attempt: 3 };

pub async fn test_key_gen<N: Network>() {
  let mut entropies = HashMap::new();
  let mut dbs = HashMap::new();
  let mut key_gens = HashMap::new();
  for i in 1 ..= 5 {
    let mut entropy = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(entropy.as_mut());
    entropies.insert(i, entropy);
    let db = MemDb::new();
    dbs.insert(i, db.clone());
    key_gens.insert(i, KeyGen::<N, MemDb>::new(db, entropies[&i].clone()));
  }

  let mut all_commitments = HashMap::new();
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    if let ProcessorMessage::Commitments { id, mut commitments } = key_gen
      .handle(
        &mut txn,
        CoordinatorMessage::GenerateKey {
          id: ID,
          params: ThresholdParams::new(3, 5, Participant::new(u16::try_from(i).unwrap()).unwrap())
            .unwrap(),
          shares: 1,
        },
      )
      .await
    {
      assert_eq!(id, ID);
      assert_eq!(commitments.len(), 1);
      all_commitments
        .insert(Participant::new(u16::try_from(i).unwrap()).unwrap(), commitments.swap_remove(0));
    } else {
      panic!("didn't get commitments back");
    }
    txn.commit();
  }

  // 1 is rebuilt on every step
  // 2 is rebuilt here
  // 3 ... are rebuilt once, one at each of the following steps
  let rebuild = |key_gens: &mut HashMap<_, _>, dbs: &HashMap<_, MemDb>, i| {
    key_gens.remove(&i);
    key_gens.insert(i, KeyGen::<N, _>::new(dbs[&i].clone(), entropies[&i].clone()));
  };
  rebuild(&mut key_gens, &dbs, 1);
  rebuild(&mut key_gens, &dbs, 2);

  let mut all_shares = HashMap::new();
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let ProcessorMessage::Shares { id, mut shares } = key_gen
      .handle(
        &mut txn,
        CoordinatorMessage::Commitments {
          id: ID,
          commitments: clone_without(&all_commitments, &i),
        },
      )
      .await
    {
      assert_eq!(id, ID);
      assert_eq!(shares.len(), 1);
      all_shares.insert(i, shares.swap_remove(0));
    } else {
      panic!("didn't get shares back");
    }
    txn.commit();
  }

  // Rebuild 1 and 3
  rebuild(&mut key_gens, &dbs, 1);
  rebuild(&mut key_gens, &dbs, 3);

  let mut res = None;
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let ProcessorMessage::GeneratedKeyPair { id, substrate_key, network_key } = key_gen
      .handle(
        &mut txn,
        CoordinatorMessage::Shares {
          id: ID,
          shares: vec![all_shares
            .iter()
            .filter_map(|(l, shares)| if i == *l { None } else { Some((*l, shares[&i].clone())) })
            .collect()],
        },
      )
      .await
    {
      assert_eq!(id, ID);
      if res.is_none() {
        res = Some((substrate_key, network_key.clone()));
      }
      assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
    } else {
      panic!("didn't get key back");
    }
    txn.commit();
  }
  let res = res.unwrap();

  // Rebuild 1 and 4
  rebuild(&mut key_gens, &dbs, 1);
  rebuild(&mut key_gens, &dbs, 4);

  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    let KeyConfirmed { mut substrate_keys, mut network_keys } = key_gen
      .confirm(&mut txn, ID.set, KeyPair(sr25519::Public(res.0), res.1.clone().try_into().unwrap()))
      .await;
    txn.commit();

    assert_eq!(substrate_keys.len(), 1);
    let substrate_keys = substrate_keys.swap_remove(0);
    assert_eq!(network_keys.len(), 1);
    let network_keys = network_keys.swap_remove(0);

    let params =
      ThresholdParams::new(3, 5, Participant::new(u16::try_from(i).unwrap()).unwrap()).unwrap();
    assert_eq!(substrate_keys.params(), params);
    assert_eq!(network_keys.params(), params);
    assert_eq!(
      (
        substrate_keys.group_key().to_bytes(),
        network_keys.group_key().to_bytes().as_ref().to_vec()
      ),
      res
    );
  }
}
