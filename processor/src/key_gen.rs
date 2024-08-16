use std::{
  io,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use blake2::{Digest, Blake2s256};
use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use dkg::{Participant, ThresholdCore, ThresholdKeys, evrf::*};

use log::info;

use serai_client::validator_sets::primitives::{Session, KeyPair};
use messages::key_gen::*;

use crate::{Get, DbTxn, Db, create_db, networks::Network};

mod generators {
  use core::any::{TypeId, Any};
  use std::{
    sync::{LazyLock, Mutex},
    collections::HashMap,
  };

  use frost::dkg::evrf::*;

  use serai_client::validator_sets::primitives::MAX_KEY_SHARES_PER_SET;

  /// A cache of the generators used by the eVRF DKG.
  ///
  /// This performs a lookup of the Ciphersuite to its generators. Since the Ciphersuite is a
  /// generic, this takes advantage of `Any`. This static is isolated in a module to ensure
  /// correctness can be evaluated solely by reviewing these few lines of code.
  ///
  /// This is arguably over-engineered as of right now, as we only need generators for Ristretto
  /// and N::Curve. By having this HashMap, we enable de-duplication of the Ristretto == N::Curve
  /// case, and we automatically support the n-curve case (rather than hard-coding to the 2-curve
  /// case).
  static GENERATORS: LazyLock<Mutex<HashMap<TypeId, &'static (dyn Send + Sync + Any)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

  pub(crate) fn generators<C: EvrfCurve>() -> &'static EvrfGenerators<C> {
    GENERATORS
      .lock()
      .unwrap()
      .entry(TypeId::of::<C>())
      .or_insert_with(|| {
        // If we haven't prior needed generators for this Ciphersuite, generate new ones
        Box::leak(Box::new(EvrfGenerators::<C>::new(
          ((MAX_KEY_SHARES_PER_SET * 2 / 3) + 1).try_into().unwrap(),
          MAX_KEY_SHARES_PER_SET.try_into().unwrap(),
        )))
      })
      .downcast_ref()
      .unwrap()
  }
}
use generators::generators;

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
    // GeneratedKeysDb, KeysDb use `()` for their value as we manually serialize their values
    // TODO: Don't do that
    GeneratedKeysDb: (session: &Session) -> (),
    // These do assume a key is only used once across sets, which holds true if the threshold is
    // honest
    // TODO: Remove this assumption
    KeysDb: (network_key: &[u8]) -> (),
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
    substrate_keys: &[ThresholdKeys<Ristretto>],
    network_keys: &[ThresholdKeys<N::Curve>],
  ) {
    let mut keys = Zeroizing::new(vec![]);
    for (substrate_keys, network_keys) in substrate_keys.iter().zip(network_keys) {
      keys.extend(substrate_keys.serialize().as_slice());
      keys.extend(network_keys.serialize().as_slice());
    }
    txn.put(Self::key(session), keys);
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

  Returns the coerced keys and faulty participants.
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
        let mut rng = ChaCha20Rng::from_seed(Blake2s256::digest(key).into());
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

impl<N: Network, D: Db> KeyGen<N, D> {
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
    // We only have these if we were told to generate a key for this session
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
    fn context<N: Network>(session: Session, key_context: &[u8]) -> [u8; 32] {
      // TODO2: Also embed the chain ID/genesis block
      let mut transcript = RecommendedTranscript::new(b"Serai eVRF Key Gen");
      transcript.append_message(b"network", N::ID);
      transcript.append_message(b"session", session.0.to_le_bytes());
      transcript.append_message(b"key", key_context);
      (&(&transcript.challenge(b"context"))[.. 32]).try_into().unwrap()
    }

    match msg {
      CoordinatorMessage::GenerateKey { session, threshold, evrf_public_keys } => {
        info!("Generating new key. Session: {session:?}");

        // Unzip the vector of eVRF keys
        let substrate_evrf_public_keys =
          evrf_public_keys.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let network_evrf_public_keys =
          evrf_public_keys.into_iter().map(|(_, key)| key).collect::<Vec<_>>();

        let mut participation = Vec::with_capacity(2048);
        let mut faulty = HashSet::new();

        // Participate for both Substrate and the network
        fn participate<C: EvrfCurve>(
          context: [u8; 32],
          threshold: u16,
          evrf_public_keys: &[impl AsRef<[u8]>],
          evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
          faulty: &mut HashSet<Participant>,
          output: &mut impl io::Write,
        ) {
          let (coerced_keys, faulty_is) = coerce_keys::<C>(evrf_public_keys);
          for faulty_i in faulty_is {
            faulty.insert(faulty_i);
          }
          let participation = EvrfDkg::<C>::participate(
            &mut OsRng,
            generators(),
            context,
            threshold,
            &coerced_keys,
            evrf_private_key,
          );
          participation.unwrap().write(output).unwrap();
        }
        participate::<Ristretto>(
          context::<N>(session, SUBSTRATE_KEY_CONTEXT),
          threshold,
          &substrate_evrf_public_keys,
          &self.substrate_evrf_private_key,
          &mut faulty,
          &mut participation,
        );
        participate::<N::Curve>(
          context::<N>(session, NETWORK_KEY_CONTEXT),
          threshold,
          &network_evrf_public_keys,
          &self.network_evrf_private_key,
          &mut faulty,
          &mut participation,
        );

        // Save the params
        ParamsDb::set(
          txn,
          &session,
          &(threshold, substrate_evrf_public_keys, network_evrf_public_keys),
        );

        // Send back our Participation and all faulty parties
        let mut faulty = faulty.into_iter().collect::<Vec<_>>();
        faulty.sort();

        let mut res = Vec::with_capacity(faulty.len() + 1);
        for faulty in faulty {
          res.push(ProcessorMessage::Blame { session, participant: faulty });
        }
        res.push(ProcessorMessage::Participation { session, participation });

        res
      }

      CoordinatorMessage::Participation { session, participant, participation } => {
        info!("received participation from {:?} for {:?}", participant, session);

        let (threshold, substrate_evrf_public_keys, network_evrf_public_keys) =
          ParamsDb::get(txn, &session).unwrap();

        let n = substrate_evrf_public_keys
          .len()
          .try_into()
          .expect("performing a key gen with more than u16::MAX participants");

        // Read these `Participation`s
        // If they fail basic sanity checks, fail fast
        let (substrate_participation, network_participation) = {
          let network_participation_start_pos = {
            let mut participation = participation.as_slice();
            let start_len = participation.len();

            let blame = vec![ProcessorMessage::Blame { session, participant }];
            let Ok(substrate_participation) =
              Participation::<Ristretto>::read(&mut participation, n)
            else {
              return blame;
            };
            let len_at_network_participation_start_pos = participation.len();
            let Ok(network_participation) = Participation::<N::Curve>::read(&mut participation, n)
            else {
              return blame;
            };

            // If they added random noise after their participations, they're faulty
            // This prevents DoS by causing a slash upon such spam
            if !participation.is_empty() {
              return blame;
            }

            // If we've already generated these keys, we don't actually need to save these
            // participations and continue. We solely have to verify them, as to identify malicious
            // participants and prevent DoSs, before returning
            if txn.get(GeneratedKeysDb::key(&session)).is_some() {
              info!("already finished generating a key for {:?}", session);

              match EvrfDkg::<Ristretto>::verify(
                &mut OsRng,
                generators(),
                context::<N>(session, SUBSTRATE_KEY_CONTEXT),
                threshold,
                // Ignores the list of participants who were faulty, as they were prior blamed
                &coerce_keys::<Ristretto>(&substrate_evrf_public_keys).0,
                &HashMap::from([(participant, substrate_participation)]),
              )
              .unwrap()
              {
                VerifyResult::Valid(_) | VerifyResult::NotEnoughParticipants => {}
                VerifyResult::Invalid(faulty) => {
                  assert_eq!(faulty, vec![participant]);
                  return vec![ProcessorMessage::Blame { session, participant }];
                }
              }

              match EvrfDkg::<N::Curve>::verify(
                &mut OsRng,
                generators(),
                context::<N>(session, NETWORK_KEY_CONTEXT),
                threshold,
                // Ignores the list of participants who were faulty, as they were prior blamed
                &coerce_keys::<N::Curve>(&network_evrf_public_keys).0,
                &HashMap::from([(participant, network_participation)]),
              )
              .unwrap()
              {
                VerifyResult::Valid(_) | VerifyResult::NotEnoughParticipants => return vec![],
                VerifyResult::Invalid(faulty) => {
                  assert_eq!(faulty, vec![participant]);
                  return vec![ProcessorMessage::Blame { session, participant }];
                }
              }
            }

            // Return the position the network participation starts at
            start_len - len_at_network_participation_start_pos
          };

          // Instead of re-serializing the `Participation`s we read, we just use the relevant
          // sections of the existing byte buffer
          (
            participation[.. network_participation_start_pos].to_vec(),
            participation[network_participation_start_pos ..].to_vec(),
          )
        };

        // Since these are valid `Participation`s, save them
        let (mut substrate_participations, mut network_participations) =
          ParticipationDb::get(txn, &session)
            .unwrap_or((HashMap::with_capacity(1), HashMap::with_capacity(1)));
        assert!(
          substrate_participations.insert(participant, substrate_participation).is_none() &&
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
          let mut evrf_public_keys_mut = substrate_evrf_public_keys.clone();
          for i in substrate_participations.keys() {
            let evrf_public_key = substrate_evrf_public_keys[usize::from(u16::from(*i)) - 1];

            // Remove this key from the Vec to prevent double-counting
            /*
              Double-counting would be a risk if multiple participants shared an eVRF public key
              and participated. This code does still allow such participants (in order to let
              participants be weighted), and any one of them participating will count as all
              participating. This is fine as any one such participant will be able to decrypt
              the shares for themselves and all other participants, so this is still a key
              generated by an amount of participants who could simply reconstruct the key.
            */
            let start_len = evrf_public_keys_mut.len();
            evrf_public_keys_mut.retain(|key| *key != evrf_public_key);
            let end_len = evrf_public_keys_mut.len();
            let count = start_len - end_len;

            participating_weight += count;
          }
          if participating_weight < usize::from(threshold) {
            return vec![];
          }
        }

        // If we now have the threshold participating, verify their `Participation`s
        fn verify_dkg<N: Network, C: EvrfCurve>(
          txn: &mut impl DbTxn,
          session: Session,
          true_if_substrate_false_if_network: bool,
          threshold: u16,
          evrf_public_keys: &[impl AsRef<[u8]>],
          substrate_participations: &mut HashMap<Participant, Vec<u8>>,
          network_participations: &mut HashMap<Participant, Vec<u8>>,
        ) -> Result<EvrfDkg<C>, Vec<ProcessorMessage>> {
          // Parse the `Participation`s
          let participations = (if true_if_substrate_false_if_network {
            &*substrate_participations
          } else {
            &*network_participations
          })
          .iter()
          .map(|(key, participation)| {
            (
              *key,
              Participation::read(
                &mut participation.as_slice(),
                evrf_public_keys.len().try_into().unwrap(),
              )
              .expect("prior read participation was invalid"),
            )
          })
          .collect();

          // Actually call verify on the DKG
          match EvrfDkg::<C>::verify(
            &mut OsRng,
            generators(),
            context::<N>(
              session,
              if true_if_substrate_false_if_network {
                SUBSTRATE_KEY_CONTEXT
              } else {
                NETWORK_KEY_CONTEXT
              },
            ),
            threshold,
            // Ignores the list of participants who were faulty, as they were prior blamed
            &coerce_keys::<C>(evrf_public_keys).0,
            &participations,
          )
          .unwrap()
          {
            // If the DKG was valid, return it
            VerifyResult::Valid(dkg) => Ok(dkg),
            // This DKG had faulty participants, so create blame messages for them
            VerifyResult::Invalid(faulty) => {
              let mut blames = vec![];
              for participant in faulty {
                // Remove from both maps for simplicity's sake
                // There's no point in having one DKG complete yet not the other
                assert!(substrate_participations.remove(&participant).is_some());
                assert!(network_participations.remove(&participant).is_some());
                blames.push(ProcessorMessage::Blame { session, participant });
              }
              // Since we removed `Participation`s, write the updated versions to the database
              ParticipationDb::set(
                txn,
                &session,
                &(substrate_participations.clone(), network_participations.clone()),
              );
              Err(blames)?
            }
            VerifyResult::NotEnoughParticipants => {
              // This is the first DKG, and we checked we were at the threshold OR
              // This is the second DKG, as the first had no invalid participants, so we're still
              // at the threshold
              panic!("not enough participants despite checking we were at the threshold")
            }
          }
        }

        let substrate_dkg = match verify_dkg::<N, Ristretto>(
          txn,
          session,
          true,
          threshold,
          &substrate_evrf_public_keys,
          &mut substrate_participations,
          &mut network_participations,
        ) {
          Ok(dkg) => dkg,
          // If we had any blames, immediately return them as necessary for the safety of
          // `verify_dkg` (it assumes we don't call it again upon prior errors)
          Err(blames) => return blames,
        };

        let network_dkg = match verify_dkg::<N, N::Curve>(
          txn,
          session,
          false,
          threshold,
          &network_evrf_public_keys,
          &mut substrate_participations,
          &mut network_participations,
        ) {
          Ok(dkg) => dkg,
          Err(blames) => return blames,
        };

        // Get our keys from each DKG
        // TODO: Some of these keys may be decrypted by us, yet not actually meant for us, if
        // another validator set our eVRF public key as their eVRF public key. We either need to
        // ensure the coordinator tracks amount of shares we're supposed to have by the eVRF public
        // keys OR explicitly reduce to the keys we're supposed to have based on our `i` index.
        let substrate_keys = substrate_dkg.keys(&self.substrate_evrf_private_key);
        let mut network_keys = network_dkg.keys(&self.network_evrf_private_key);
        // Tweak the keys for the network
        for network_keys in &mut network_keys {
          N::tweak_keys(network_keys);
        }
        GeneratedKeysDb::save_keys::<N>(txn, &session, &substrate_keys, &network_keys);

        // Since no one we verified was invalid, and we had the threshold, yield the new keys
        vec![ProcessorMessage::GeneratedKeyPair {
          session,
          substrate_key: substrate_keys[0].group_key().to_bytes(),
          // TODO: This can be made more efficient since tweaked keys may be a subset of keys
          network_key: network_keys[0].group_key().to_bytes().as_ref().to_vec(),
        }]
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
