// TODO

use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};
use dkg::{Participant, ThresholdParams, evrf::*};

use serai_db::{DbTxn, Db, MemDb};

use sp_application_crypto::sr25519;
use serai_client::validator_sets::primitives::{Session, KeyPair};

use messages::key_gen::*;
use crate::{
  networks::Network,
  key_gen::{KeyConfirmed, KeyGen},
};

const SESSION: Session = Session(1);

pub fn test_key_gen<N: Network>() {
  let mut dbs = HashMap::new();
  let mut substrate_evrf_keys = HashMap::new();
  let mut network_evrf_keys = HashMap::new();
  let mut evrf_public_keys = vec![];
  let mut key_gens = HashMap::new();
  for i in 1 ..= 5 {
    let db = MemDb::new();
    dbs.insert(i, db.clone());

    let substrate_evrf_key = Zeroizing::new(
      <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng),
    );
    substrate_evrf_keys.insert(i, substrate_evrf_key.clone());
    let network_evrf_key = Zeroizing::new(
      <<N::Curve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng),
    );
    network_evrf_keys.insert(i, network_evrf_key.clone());

    evrf_public_keys.push((
      (<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * *substrate_evrf_key)
        .to_bytes(),
      (<<N::Curve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * *network_evrf_key)
        .to_bytes()
        .as_ref()
        .to_vec(),
    ));
    key_gens
      .insert(i, KeyGen::<N, MemDb>::new(db, substrate_evrf_key.clone(), network_evrf_key.clone()));
  }

  let mut participations = HashMap::new();
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    let mut msgs = key_gen.handle(
      &mut txn,
      CoordinatorMessage::GenerateKey {
        session: SESSION,
        threshold: 3,
        evrf_public_keys: evrf_public_keys.clone(),
      },
    );
    assert_eq!(msgs.len(), 1);
    let ProcessorMessage::Participation { session, participation } = msgs.swap_remove(0) else {
      panic!("didn't get a participation")
    };
    assert_eq!(session, SESSION);
    participations.insert(i, participation);
    txn.commit();
  }

  let mut res = None;
  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    for j in 1 ..= 5 {
      let mut msgs = key_gen.handle(
        &mut txn,
        CoordinatorMessage::Participation {
          session: SESSION,
          participant: Participant::new(u16::try_from(j).unwrap()).unwrap(),
          participation: participations[&j].clone(),
        },
      );
      if j != 3 {
        assert!(msgs.is_empty());
      }
      if j == 3 {
        assert_eq!(msgs.len(), 1);
        let ProcessorMessage::GeneratedKeyPair { session, substrate_key, network_key } =
          msgs.swap_remove(0)
        else {
          panic!("didn't get a generated key pair")
        };
        assert_eq!(session, SESSION);

        if res.is_none() {
          res = Some((substrate_key, network_key.clone()));
        }
        assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
      }
    }

    txn.commit();
  }
  let res = res.unwrap();

  for i in 1 ..= 5 {
    let key_gen = key_gens.get_mut(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    let KeyConfirmed { mut substrate_keys, mut network_keys } = key_gen.confirm(
      &mut txn,
      SESSION,
      &KeyPair(sr25519::Public(res.0), res.1.clone().try_into().unwrap()),
    );
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
