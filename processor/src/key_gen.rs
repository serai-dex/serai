use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use blake2::{Digest, Blake2s256};
use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use frost::dkg::{Participant, ThresholdCore, ThresholdKeys, evrf::*};

use log::info;

use serai_client::validator_sets::primitives::{Session, KeyPair};
use messages::key_gen::*;

use crate::{Get, DbTxn, Db, create_db, networks::Network};

#[derive(Debug)]
pub struct KeyConfirmed<C: Ciphersuite> {
  pub substrate_keys: Vec<ThresholdKeys<Ristretto>>,
  pub network_keys: Vec<ThresholdKeys<C>>,
}

create_db!(
  KeyGenDb {
    ParamsDb: (session: &Session) -> (u16, Vec<[u8; 32]>, Vec<Vec<u8>>),
    ParticipationDb: (session: &Session) -> (
      HashMap<Participant, Vec<u8>>,
      HashMap<Participant, Vec<u8>>,
    ),
    GeneratedKeysDb: (session: &Session) -> Vec<u8>,
    // These do assume a key is only used once across sets, which holds true if the threshold is
    // honest
    // TODO: Remove this assumption
    KeysDb: (network_key: &[u8]) -> Vec<u8>,
    SessionDb: (network_key: &[u8]) -> Session,
    NetworkKeyDb: (session: Session) -> Vec<u8>,
  }
);

impl GeneratedKeysDb {
  #[allow(clippy::type_complexity)]
  fn read_keys<N: Network>(
    getter: &impl Get,
    key: &[u8],
  ) -> Option<(Vec<u8>, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    let keys_vec = getter.get(key)?;
    let mut keys_ref: &[u8] = keys_vec.as_ref();

    let mut substrate_keys = vec![];
    let mut network_keys = vec![];
    while !keys_ref.is_empty() {
      substrate_keys.push(ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap()));
      let mut these_network_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
      N::tweak_keys(&mut these_network_keys);
      network_keys.push(these_network_keys);
    }
    Some((keys_vec, (substrate_keys, network_keys)))
  }

  fn save_keys<N: Network>(
    txn: &mut impl DbTxn,
    session: &Session,
    substrate_keys: &[ThresholdCore<Ristretto>],
    network_keys: &[ThresholdKeys<N::Curve>],
  ) {
    let mut keys = Zeroizing::new(vec![]);
    for (substrate_keys, network_keys) in substrate_keys.iter().zip(network_keys) {
      keys.extend(substrate_keys.serialize().as_slice());
      keys.extend(network_keys.serialize().as_slice());
    }
    txn.put(Self::key(&session), keys);
  }
}

impl KeysDb {
  fn confirm_keys<N: Network>(
    txn: &mut impl DbTxn,
    session: Session,
    key_pair: &KeyPair,
  ) -> (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>) {
    let (keys_vec, keys) =
      GeneratedKeysDb::read_keys::<N>(txn, &GeneratedKeysDb::key(&session)).unwrap();
    assert_eq!(key_pair.0 .0, keys.0[0].group_key().to_bytes());
    assert_eq!(
      {
        let network_key: &[u8] = key_pair.1.as_ref();
        network_key
      },
      keys.1[0].group_key().to_bytes().as_ref(),
    );
    txn.put(Self::key(key_pair.1.as_ref()), keys_vec);
    NetworkKeyDb::set(txn, session, &key_pair.1.clone().into_inner());
    SessionDb::set(txn, key_pair.1.as_ref(), &session);
    keys
  }

  #[allow(clippy::type_complexity)]
  fn keys<N: Network>(
    getter: &impl Get,
    network_key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Session, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    let res =
      GeneratedKeysDb::read_keys::<N>(getter, &Self::key(network_key.to_bytes().as_ref()))?.1;
    assert_eq!(&res.1[0].group_key(), network_key);
    Some((SessionDb::get(getter, network_key.to_bytes().as_ref()).unwrap(), res))
  }

  pub fn substrate_keys_by_session<N: Network>(
    getter: &impl Get,
    session: Session,
  ) -> Option<Vec<ThresholdKeys<Ristretto>>> {
    let network_key = NetworkKeyDb::get(getter, session)?;
    Some(GeneratedKeysDb::read_keys::<N>(getter, &Self::key(&network_key))?.1 .0)
  }
}

/*
  On the Serai blockchain, users specify their public keys on the embedded curves. Substrate does
  not have the libraries for the embedded curves and is unable to evaluate if the keys are valid
  or not.

  We could add the libraries for the embedded curves to the blockchain, yet this would be a
  non-trivial scope for what's effectively an embedded context. It'd also permanently bind our
  consensus to these arbitrary curves. We would have the benefit of being able to also require PoKs
  for the keys, ensuring no one uses someone else's key (creating oddities there). Since someone
  who uses someone else's key can't actually participate, all it does in effect is give more key
  shares to the holder of the private key, and make us unable to rely on eVRF keys as a secure way
  to index validators (hence the usage of `Participant` throughout the messages here).

  We could remove invalid keys from the DKG, yet this would create a view of the DKG only the
  processor (which does have the embedded curves) has. We'd need to reconcile it with the view of
  the DKG which does include all keys (even the invalid keys).

  The easiest solution is to keep the views consistent by replacing invalid keys with valid keys
  (which no one has the private key for). This keeps the view consistent. This does prevent those
  who posted invalid keys from participating, and receiving their keys, which is the understood and
  declared effect of them posting invalid keys. Since at least `t` people must honestly participate
  for the DKG to complete, and since their honest participation means they had valid keys, we do
  ensure at least `t` people participated and the DKG result can be reconstructed.

  We do lose fault tolerance, yet only by losing those faulty. Accordingly, this is accepted.
*/
fn coerce_keys<C: EvrfCurve>(
  key_bytes: &[impl AsRef<[u8]>],
) -> (Vec<<C::EmbeddedCurve as Ciphersuite>::G>, Vec<Participant>) {
  fn evrf_key<C: EvrfCurve>(key: &[u8]) -> Option<<C::EmbeddedCurve as Ciphersuite>::G> {
    let mut repr = <<C::EmbeddedCurve as Ciphersuite>::G as GroupEncoding>::Repr::default();
    if repr.as_ref().len() != key.len() {
      None?;
    }
    repr.as_mut().copy_from_slice(key);
    let point = Option::<<C::EmbeddedCurve as Ciphersuite>::G>::from(<_>::from_bytes(&repr))?;
    if bool::from(point.is_identity()) {
      None?;
    }
    Some(point)
  }

  let mut keys = Vec::with_capacity(key_bytes.len());
  let mut faulty = vec![];
  for (i, key) in key_bytes.iter().enumerate() {
    let i = Participant::new(
      1 + u16::try_from(i).expect("performing a key gen with more than u16::MAX participants"),
    )
    .unwrap();
    keys.push(match evrf_key::<C>(key.as_ref()) {
      Some(key) => key,
      None => {
        // Mark this participant faulty
        faulty.push(i);

        // Generate a random key
        let mut rng = ChaCha20Rng::from_seed(Blake2s256::digest(&key).into());
        loop {
          let mut repr = <<C::EmbeddedCurve as Ciphersuite>::G as GroupEncoding>::Repr::default();
          rng.fill_bytes(repr.as_mut());
          if let Some(key) =
            Option::<<C::EmbeddedCurve as Ciphersuite>::G>::from(<_>::from_bytes(&repr))
          {
            break key;
          }
        }
      }
    });
  }

  (keys, faulty)
}

#[derive(Debug)]
pub struct KeyGen<N: Network, D: Db> {
  db: D,
  substrate_evrf_private_key:
    Zeroizing<<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
  network_evrf_private_key: Zeroizing<<<N::Curve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
}

impl<N: Network, D: Db> KeyGen<N, D>
where
  <<N::Curve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
    ec_divisors::DivisorCurve<FieldElement = <N::Curve as Ciphersuite>::F>,
{
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    db: D,
    substrate_evrf_private_key: Zeroizing<
      <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F,
    >,
    network_evrf_private_key: Zeroizing<<<N::Curve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
  ) -> KeyGen<N, D> {
    KeyGen { db, substrate_evrf_private_key, network_evrf_private_key }
  }

  pub fn in_set(&self, session: &Session) -> bool {
    // We determine if we're in set using if we have the parameters for a session's key generation
    ParamsDb::get(&self.db, session).is_some()
  }

  #[allow(clippy::type_complexity)]
  pub fn keys(
    &self,
    key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Session, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    // This is safe, despite not having a txn, since it's a static value
    // It doesn't change over time/in relation to other operations
    KeysDb::keys::<N>(&self.db, key)
  }

  pub fn substrate_keys_by_session(
    &self,
    session: Session,
  ) -> Option<Vec<ThresholdKeys<Ristretto>>> {
    KeysDb::substrate_keys_by_session::<N>(&self.db, session)
  }

  pub fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> Vec<ProcessorMessage> {
    const SUBSTRATE_KEY_CONTEXT: &[u8] = b"substrate";
    const NETWORK_KEY_CONTEXT: &[u8] = b"network";
    let context = |session: Session, key| {
      // TODO2: Also embed the chain ID/genesis block
      let mut transcript = RecommendedTranscript::new(b"Serai eVRF Key Gen");
      transcript.append_message(b"network", N::ID);
      transcript.append_message(b"session", session.0.to_le_bytes());
      transcript.append_message(b"key", key);
      <[u8; 32]>::try_from(&(&transcript.challenge(b"context"))[.. 32]).unwrap()
    };

    match msg {
      CoordinatorMessage::GenerateKey { session, threshold, evrf_public_keys } => {
        info!("Generating new key. Session: {session:?}");

        let substrate_evrf_public_keys =
          evrf_public_keys.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let network_evrf_public_keys =
          evrf_public_keys.into_iter().map(|(_, key)| key).collect::<Vec<_>>();

        // Save the params
        ParamsDb::set(
          txn,
          &session,
          &(threshold, substrate_evrf_public_keys, network_evrf_public_keys),
        );

        let mut participation = Vec::with_capacity(2048);
        let mut faulty = HashSet::new();
        {
          let (coerced_keys, faulty_is) = coerce_keys::<Ristretto>(&substrate_evrf_public_keys);
          for faulty_i in faulty_is {
            faulty.insert(faulty_i);
          }
          let participation = EvrfDkg::<Ristretto>::participate(
            &mut OsRng,
            todo!("TODO"),
            context(session, SUBSTRATE_KEY_CONTEXT),
            threshold,
            &coerced_keys,
            &self.substrate_evrf_private_key,
          )
          .unwrap()
          .write(&mut participation)
          .unwrap();
        }
        {
          let (coerced_keys, faulty_is) = coerce_keys::<N::Curve>(&network_evrf_public_keys);
          for faulty_i in faulty_is {
            faulty.insert(faulty_i);
          }
          EvrfDkg::<N::Curve>::participate(
            &mut OsRng,
            todo!("TODO"),
            context(session, NETWORK_KEY_CONTEXT),
            threshold,
            &coerced_keys,
            &self.network_evrf_private_key,
          )
          .unwrap()
          .write(&mut participation)
          .unwrap();
        }

        // Send back our Participation and all faulty parties
        let mut faulty = faulty.into_iter().collect::<Vec<_>>();
        faulty.sort();

        let mut res = Vec::with_capacity(1 + faulty.len());
        res.push(ProcessorMessage::Participation { session, participation });
        for faulty in faulty {
          res.push(ProcessorMessage::Blame { session, participant: faulty });
        }

        res
      }

      CoordinatorMessage::Participation { session, participant, participation } => {
        info!("Received participation from {:?}", participant);

        // TODO: Read Pariticpations, declare faulty if necessary, then re-serialize
        let substrate_participation: Vec<u8> = todo!("TODO");
        let network_participation: Vec<u8> = todo!("TODO");

        let (threshold, substrate_evrf_public_keys, network_evrf_public_keys) =
          ParamsDb::get(txn, &session).unwrap();
        let (mut substrate_participations, mut network_participations) =
          ParticipationDb::get(txn, &session)
            .unwrap_or((HashMap::with_capacity(1), HashMap::with_capacity(1)));
        assert!(
          substrate_participations.insert(participant, substrate_participation).is_none(),
          "received participation for someone multiple times"
        );
        assert!(
          network_participations.insert(participant, network_participation).is_none(),
          "received participation for someone multiple times"
        );
        ParticipationDb::set(
          txn,
          &session,
          &(substrate_participations.clone(), network_participations.clone()),
        );

        // This block is taken from the eVRF DKG itself to evaluate the amount participating
        {
          let mut participating_weight = 0;
          // This uses the Substrate maps as the maps are kept in synchrony
          let mut evrf_public_keys = substrate_evrf_public_keys.clone();
          for i in substrate_participations.keys() {
            let evrf_public_key = evrf_public_keys[usize::from(u16::from(*i)) - 1];

            // Removes from Vec to prevent double-counting
            let start_len = evrf_public_keys.len();
            evrf_public_keys.retain(|key| *key != evrf_public_key);
            let end_len = evrf_public_keys.len();
            let count = start_len - end_len;

            participating_weight += count;
          }
          if participating_weight < usize::from(threshold) {
            return vec![];
          }
        }

        let mut res = Vec::with_capacity(1);
        let substrate_dkg = match EvrfDkg::<Ristretto>::verify(
          &mut OsRng,
          &todo!("TODO"),
          context(session, SUBSTRATE_KEY_CONTEXT),
          threshold,
          // Ignores the list of participants who couldn't have their keys coerced due to prior
          // handling those
          &coerce_keys::<Ristretto>(&substrate_evrf_public_keys).0,
          &substrate_participations
            .iter()
            .map(|(key, participation)| {
              (
                *key,
                Participation::read(
                  &mut participation.as_slice(),
                  substrate_evrf_public_keys
                    .len()
                    .try_into()
                    .expect("performing a key gen with more than u16::MAX participants"),
                )
                .expect("prior read participation was invalid"),
              )
            })
            .collect(),
        )
        .unwrap()
        {
          VerifyResult::Valid(dkg) => dkg,
          VerifyResult::Invalid(faulty) => {
            for participant in faulty {
              // Remove from both maps for simplicity's sake
              // There's no point in having one DKG complete yet not the other
              assert!(substrate_participations.remove(&participant).is_some());
              assert!(network_participations.remove(&participant).is_some());
              res.push(ProcessorMessage::Blame { session, participant });
            }
            ParticipationDb::set(
              txn,
              &session,
              &(substrate_participations.clone(), network_participations.clone()),
            );
            return res;
          }
          VerifyResult::NotEnoughParticipants => {
            panic!("not enough participants despite checking we were at the threshold")
          }
        };
        let network_dkg = match EvrfDkg::<N::Curve>::verify(
          &mut OsRng,
          &todo!("TODO"),
          context(session, NETWORK_KEY_CONTEXT),
          threshold,
          // Ignores the list of participants who couldn't have their keys coerced due to prior
          // handling those
          &coerce_keys::<N::Curve>(&network_evrf_public_keys).0,
          &network_participations
            .iter()
            .map(|(key, participation)| {
              (
                *key,
                Participation::read(
                  &mut participation.as_slice(),
                  network_evrf_public_keys
                    .len()
                    .try_into()
                    .expect("performing a key gen with more than u16::MAX participants"),
                )
                .expect("prior read participation was invalid"),
              )
            })
            .collect(),
        )
        .unwrap()
        {
          VerifyResult::Valid(dkg) => dkg,
          VerifyResult::Invalid(faulty) => {
            for participant in faulty {
              assert!(substrate_participations.remove(&participant).is_some());
              assert!(network_participations.remove(&participant).is_some());
              res.push(ProcessorMessage::Blame { session, participant });
            }
            ParticipationDb::set(
              txn,
              &session,
              &(substrate_participations.clone(), network_participations.clone()),
            );
            return res;
          }
          VerifyResult::NotEnoughParticipants => {
            // We may have lost the required amount of participants when doing the Substrate DKG
            return res;
          }
        };

        /*
          let mut these_network_keys = ThresholdKeys::new(these_network_keys);
          N::tweak_keys(&mut these_network_keys);

          substrate_keys.push(these_substrate_keys);
          network_keys.push(these_network_keys);

          let mut generated_substrate_key = None;
          let mut generated_network_key = None;
          for keys in substrate_keys.iter().zip(&network_keys) {
            if generated_substrate_key.is_none() {
              generated_substrate_key = Some(keys.0.group_key());
              generated_network_key = Some(keys.1.group_key());
            } else {
              assert_eq!(generated_substrate_key, Some(keys.0.group_key()));
              assert_eq!(generated_network_key, Some(keys.1.group_key()));
            }
          }

          GeneratedKeysDb::save_keys::<N>(txn, &id, &substrate_keys, &network_keys);

          ProcessorMessage::GeneratedKeyPair {
            id,
            substrate_key: generated_substrate_key.unwrap().to_bytes(),
            // TODO: This can be made more efficient since tweaked keys may be a subset of keys
            network_key: generated_network_key.unwrap().to_bytes().as_ref().to_vec(),
          }
        */

        todo!("TODO")
      }
    }
  }

  // This should only be called if we're participating, hence taking our instance
  #[allow(clippy::unused_self)]
  pub fn confirm(
    &mut self,
    txn: &mut D::Transaction<'_>,
    session: Session,
    key_pair: &KeyPair,
  ) -> KeyConfirmed<N::Curve> {
    info!(
      "Confirmed key pair {} {} for {:?}",
      hex::encode(key_pair.0),
      hex::encode(&key_pair.1),
      session,
    );

    let (substrate_keys, network_keys) = KeysDb::confirm_keys::<N>(txn, session, key_pair);

    KeyConfirmed { substrate_keys, network_keys }
  }
}
