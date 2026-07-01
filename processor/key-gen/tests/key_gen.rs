use zeroize::Zeroizing;

use rand_core::{RngCore as _, OsRng};

use ciphersuite::{
  group::{ff::Field as _, GroupEncoding},
  WrappedGroup,
};
use dkg::*;

use serai_db::{DbTxn as _, Db as _, MemDb};

use serai_primitives::validator_sets::Session;
use serai_tributary_types::{TributaryValidator, TributaryValidatorSet};
use messages::key_gen::*;
use serai_processor_key_gen::{Ristretto, KeyGen, KeyGenParams};

const THRESHOLD: u16 = 3;
const PARTICIPANTS: u16 = 5;

fn test_valid_participants_inner<K: KeyGenParams>() {
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  let random_session = Session(OsRng.next_u64() as u32);

  let mut states = vec![];
  let mut tributary_validators = vec![];

  for _ in 0 .. PARTICIPANTS {
    let db = MemDb::new();

    let substrate_evrf_key =
      Zeroizing::new(<<Ristretto as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let network_evrf_key = Zeroizing::new(
      <<K::ExternalNetworkCiphersuite as Curves>::EmbeddedCurve as WrappedGroup>::F::random(
        &mut OsRng,
      ),
    );

    let serai_aux_pub = (<<Ristretto as Curves>::ToweringCurve as WrappedGroup>::generator() *
      <<Ristretto as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng))
    .to_bytes();
    let substrate_pub = (<<Ristretto as Curves>::EmbeddedCurve as WrappedGroup>::generator() *
      *substrate_evrf_key)
      .to_bytes();
    let network_pub =
      (<<K::ExternalNetworkCiphersuite as Curves>::EmbeddedCurve as WrappedGroup>::generator() *
        *network_evrf_key)
        .to_bytes()
        .as_ref()
        .to_vec();

    tributary_validators.push(TributaryValidator::new(
      serai_aux_pub,
      substrate_pub,
      network_pub,
      1,
    ));
    states.push((db, KeyGen::<K>::new(substrate_evrf_key.clone(), network_evrf_key.clone())));
  }
  let tributary_validator_set = TributaryValidatorSet::new(tributary_validators);

  let mut participations = Vec::with_capacity(usize::from(PARTICIPANTS));
  for (db, key_gen) in &mut states {
    let mut txn = db.txn();
    let substrate_evrf_public_keys =
      tributary_validator_set.evrf_networks_substrate_keys().to_vec();
    let network_evrf_public_keys = tributary_validator_set.evrf_networks_external_keys().to_vec();
    let mut messages = key_gen.handle(
      &mut txn,
      CoordinatorMessage::GenerateKey {
        session: random_session,
        threshold: THRESHOLD,
        substrate_evrf_public_keys,
        network_evrf_public_keys,
      },
    );
    txn.commit();

    assert_eq!(messages.len(), 1);
    let ProcessorMessage::Participation { session, participation } = messages.remove(0) else {
      panic!("KeyGen returned unexpected message")
    };
    assert_eq!(session, random_session);
    participations.push(participation);
  }

  let mut res = None;
  for (db, key_gen) in &mut states {
    let mut txn = db.txn();
    for (i, participation) in participations.iter().cloned().enumerate() {
      let mut messages = key_gen.handle(
        &mut txn,
        CoordinatorMessage::Participation {
          session: random_session,
          participant: Participant::new(u16::try_from(i).unwrap() + 1).unwrap(),
          participation,
        },
      );

      let handled_participations = i + 1;
      if handled_participations != usize::from(THRESHOLD) {
        assert!(messages.is_empty());
        continue;
      }

      assert_eq!(messages.len(), 1);
      let ProcessorMessage::GeneratedKeyPair { session, substrate_key, network_key } =
        messages.remove(0)
      else {
        panic!("KeyGen returned unexpected message")
      };
      assert_eq!(session, random_session);

      if res.is_none() {
        res = Some((substrate_key, network_key.clone()));
      }
      assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
    }

    txn.commit();
  }
}

fn test_some_bad_participants_inner<K: KeyGenParams>() {
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  let random_session = Session(OsRng.next_u64() as u32);

  let zero_pub_keys =
    Participant::new(1 + u16::try_from(OsRng.next_u64() % u64::from(PARTICIPANTS)).unwrap())
      .unwrap();

  let mut states = vec![];
  let mut tributary_validators = vec![];

  for i in 0 .. PARTICIPANTS {
    let db = MemDb::new();

    let substrate_evrf_key =
      Zeroizing::new(<<Ristretto as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let network_evrf_key = Zeroizing::new(
      <<K::ExternalNetworkCiphersuite as Curves>::EmbeddedCurve as WrappedGroup>::F::random(
        &mut OsRng,
      ),
    );

    if Participant::new(1 + i).unwrap() == zero_pub_keys {
      let serai_aux_pub = (<<Ristretto as Curves>::ToweringCurve as WrappedGroup>::generator() *
        <<Ristretto as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng))
      .to_bytes();
      let mut zero_ristretto_pub =
        <<<Ristretto as Curves>::EmbeddedCurve as WrappedGroup>::G as GroupEncoding>::Repr::default(
        );
      {
        let zero_ristretto_pub: &mut [u8] = zero_ristretto_pub.as_mut();
        for b in zero_ristretto_pub {
          *b = 0;
        }
      }
      let mut zero_external_pub = <
        <
          <K::ExternalNetworkCiphersuite as Curves>::EmbeddedCurve as WrappedGroup
        >::G as GroupEncoding
      >::Repr::default();
      {
        let zero_external_pub: &mut [u8] = zero_external_pub.as_mut();
        for b in zero_external_pub {
          *b = 0;
        }
      }
      tributary_validators.push(TributaryValidator::new(
        serai_aux_pub,
        zero_ristretto_pub,
        zero_external_pub.as_ref().to_vec(),
        1,
      ));
    } else {
      let serai_aux_pub = (<<Ristretto as Curves>::ToweringCurve as WrappedGroup>::generator() *
        <<Ristretto as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng))
      .to_bytes();
      let substrate_pub = (<<Ristretto as Curves>::EmbeddedCurve as WrappedGroup>::generator() *
        *substrate_evrf_key)
        .to_bytes();
      let network_pub =
        (<<K::ExternalNetworkCiphersuite as Curves>::EmbeddedCurve as WrappedGroup>::generator() *
          *network_evrf_key)
          .to_bytes()
          .as_ref()
          .to_vec();
      tributary_validators.push(TributaryValidator::new(
        serai_aux_pub,
        substrate_pub,
        network_pub,
        1,
      ));
    }
    states.push((db, KeyGen::<K>::new(substrate_evrf_key.clone(), network_evrf_key.clone())));
  }
  let tributary_validator_set = TributaryValidatorSet::new(tributary_validators);

  let mut participations = Vec::with_capacity(usize::from(PARTICIPANTS));
  for (i, (db, key_gen)) in states.iter_mut().enumerate() {
    if (i + 1) == usize::from(u16::from(zero_pub_keys)) {
      participations.push(vec![]);
      continue;
    }

    let mut txn = db.txn();
    let substrate_evrf_public_keys =
      tributary_validator_set.evrf_networks_substrate_keys().to_vec();
    let network_evrf_public_keys = tributary_validator_set.evrf_networks_external_keys().to_vec();
    let mut messages = key_gen.handle(
      &mut txn,
      CoordinatorMessage::GenerateKey {
        session: random_session,
        threshold: THRESHOLD,
        substrate_evrf_public_keys,
        network_evrf_public_keys,
      },
    );
    txn.commit();

    assert_eq!(messages.len(), 3);

    // One blame for each invalid key
    let ProcessorMessage::Blame { session, participant } = messages.remove(0) else {
      panic!("KeyGen returned unexpected message")
    };
    assert_eq!((session, participant), (random_session, zero_pub_keys));
    let ProcessorMessage::Blame { session, participant } = messages.remove(0) else {
      panic!("KeyGen returned unexpected message")
    };
    assert_eq!((session, participant), (random_session, zero_pub_keys));

    let ProcessorMessage::Participation { session, participation } = messages.remove(0) else {
      panic!("KeyGen returned unexpected message")
    };
    assert_eq!(session, random_session);

    participations.push(participation);
  }

  let mut res = None;

  for (i, (db, key_gen)) in states.iter_mut().enumerate() {
    if (i + 1) == usize::from(u16::from(zero_pub_keys)) {
      continue;
    }

    let mut txn = db.txn();
    for (i, participation) in participations.iter().cloned().enumerate() {
      if (i + 1) == usize::from(u16::from(zero_pub_keys)) {
        continue;
      }

      let mut messages = key_gen.handle(
        &mut txn,
        CoordinatorMessage::Participation {
          session: random_session,
          participant: Participant::new(u16::try_from(i).unwrap() + 1).unwrap(),
          participation,
        },
      );

      let mut handled_participations = i + 1;
      if handled_participations > usize::from(u16::from(zero_pub_keys)) {
        handled_participations -= 1;
      }
      if handled_participations != usize::from(THRESHOLD) {
        assert!(messages.is_empty());
        continue;
      }

      assert_eq!(messages.len(), 1);
      let ProcessorMessage::GeneratedKeyPair { session, substrate_key, network_key } =
        messages.remove(0)
      else {
        panic!("KeyGen returned unexpected message")
      };
      assert_eq!(session, random_session);

      if res.is_none() {
        res = Some((substrate_key, network_key.clone()));
      }
      assert_eq!(res.as_ref().unwrap(), &(substrate_key, network_key));
    }

    txn.commit();
  }
}

pub(crate) struct RistrettoKeyGenParams;
impl KeyGenParams for RistrettoKeyGenParams {
  const ID: &'static str = "Ristretto";

  type ExternalNetworkCiphersuite = Ristretto;
}

#[test]
fn test_ristretto() {
  test_valid_participants_inner::<RistrettoKeyGenParams>();
  test_some_bad_participants_inner::<RistrettoKeyGenParams>();
}
