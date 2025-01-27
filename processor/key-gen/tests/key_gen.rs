use zeroize::Zeroizing;

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};
use dkg::{Participant, evrf::*};

use serai_db::{DbTxn, Db, MemDb};

use messages::key_gen::*;
use serai_processor_key_gen::{KeyGen, KeyGenParams};
use serai_validator_sets_primitives::Session;

const SESSION: Session = Session(1);

pub(crate) struct RistrettoKeyGenParams;
impl KeyGenParams for RistrettoKeyGenParams {
  const ID: &'static str = "Ristretto";

  type ExternalNetworkCiphersuite = Ristretto;
}

#[test]
fn test_valid_participants() {
  test_valid_participants_inner::<RistrettoKeyGenParams>();
}

#[test]
fn test_some_bad_participants() {
  test_some_bad_participants_inner::<RistrettoKeyGenParams>();
}

fn test_valid_participants_inner<K: KeyGenParams>() {
  let mut dbs = Vec::new();
  let mut substrate_evrf_keys = Vec::new();
  let mut network_evrf_keys = Vec::new();
  let mut evrf_public_keys = vec![];
  let mut key_gens = Vec::new();

  for _ in 0 .. 5 {
    let db = MemDb::new();
    dbs.push(db.clone());

    let substrate_evrf_key = Zeroizing::new(
      <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng),
    );
    substrate_evrf_keys.push(substrate_evrf_key.clone());
    let network_evrf_key = Zeroizing::new(
      <<K::ExternalNetworkCiphersuite as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(
        &mut OsRng,
      ),
    );
    network_evrf_keys.push(network_evrf_key.clone());

    evrf_public_keys.push((
      (<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * *substrate_evrf_key)
        .to_bytes(),
      (<<K::ExternalNetworkCiphersuite as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() *
        *network_evrf_key)
        .to_bytes()
        .as_ref()
        .to_vec(),
    ));
    key_gens.push(KeyGen::<K>::new(substrate_evrf_key.clone(), network_evrf_key.clone()));
  }

  let mut participations = Vec::with_capacity(key_gens.len());

  for i in 0 .. 5 {
    let mut tx = dbs[i].txn();

    let mut messages = key_gens[i].handle(
      &mut tx,
      CoordinatorMessage::GenerateKey {
        session: SESSION,
        threshold: 3,
        evrf_public_keys: evrf_public_keys.clone(),
      },
    );

    assert_eq!(messages.len(), 1);

    let Some(ProcessorMessage::Participation { session, participation }) = messages.pop() else {
      panic!("KeyGen returned unexpected message.")
    };

    assert_eq!(session, SESSION);

    participations.push(participation);

    tx.commit();
  }

  let mut res = None;

  for i in 0 .. 5 {
    let mut tx = dbs[i].txn();
    let key_gen = &mut key_gens[i];

    for (i, participation) in participations.iter().cloned().enumerate() {
      let mut messages = key_gen.handle(
        &mut tx,
        CoordinatorMessage::Participation {
          session: SESSION,
          participant: Participant::new(i as u16 + 1).unwrap(),
          participation,
        },
      );

      if i != 2 {
        assert!(messages.is_empty());
      } else {
        let Some(ProcessorMessage::GeneratedKeyPair { session, substrate_key, network_key }) =
          messages.pop()
        else {
          panic!("KeyGen returned unexpected message.")
        };

        assert_eq!(session, SESSION);

        if res.is_none() {
          res = Some((substrate_key, network_key.clone()));
        }
        assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
      }
    }

    tx.commit();
  }
}

fn test_some_bad_participants_inner<K: KeyGenParams>() {
  let mut dbs = Vec::new();
  let mut substrate_evrf_keys = Vec::new();
  let mut network_evrf_keys = Vec::new();
  let mut evrf_public_keys = vec![];
  let mut key_gens = Vec::new();

  for i in 0 .. 5 {
    let db = MemDb::new();
    dbs.push(db.clone());

    let substrate_evrf_key = Zeroizing::new(
      <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng),
    );
    substrate_evrf_keys.push(substrate_evrf_key.clone());
    let network_evrf_key = Zeroizing::new(
      <<K::ExternalNetworkCiphersuite as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::random(
        &mut OsRng,
      ),
    );
    network_evrf_keys.push(network_evrf_key.clone());

    if i == 0 {
      evrf_public_keys.push(([0; 32], [0; 32].to_vec()))
    } else {
      evrf_public_keys.push(
        (
          (<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() *
            *substrate_evrf_key)
            .to_bytes(),
          (<<K::ExternalNetworkCiphersuite as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator(
          ) * *network_evrf_key)
            .to_bytes()
            .as_ref()
            .to_vec(),
        ),
      );
    }
    key_gens.push(KeyGen::<K>::new(substrate_evrf_key.clone(), network_evrf_key.clone()));
  }

  let mut participations = Vec::with_capacity(key_gens.len());

  for i in 0 .. 5 {
    if i == 0 {
      continue;
    }

    let mut tx = dbs[i].txn();

    let mut messages = key_gens[i].handle(
      &mut tx,
      CoordinatorMessage::GenerateKey {
        session: SESSION,
        threshold: 3,
        evrf_public_keys: evrf_public_keys.clone(),
      },
    );

    assert_eq!(messages.len(), 3);

    let ProcessorMessage::Blame { session, participant } = &messages[0] else {
      panic!("KeyGen returned unexpected message.")
    };
    assert_eq!((session, participant), (&SESSION, &Participant::new(1).unwrap()));

    let Some(ProcessorMessage::Participation { session, participation }) = messages.pop() else {
      panic!("KeyGen returned unexpected message.")
    };

    assert_eq!(session, SESSION);

    participations.push(participation);

    tx.commit();
  }

  let mut res = None;

  for i in 0 .. 5 {
    let mut tx = dbs[i].txn();
    let key_gen = &mut key_gens[i];

    for (i, participation) in participations.iter().cloned().enumerate() {
      let mut messages = key_gen.handle(
        &mut tx,
        CoordinatorMessage::Participation {
          session: SESSION,
          participant: Participant::new(i as u16 + 1).unwrap(),
          participation,
        },
      );

      if i != 2 {
        assert!(messages.is_empty());
      } else {
        let Some(ProcessorMessage::GeneratedKeyPair { session, substrate_key, network_key }) =
          messages.pop()
        else {
          panic!("KeyGen returned unexpected message.")
        };

        assert_eq!(session, SESSION);

        if res.is_none() {
          res = Some((substrate_key, network_key.clone()));
        }
        assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
      }
    }

    tx.commit();
  }
}
