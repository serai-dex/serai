#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{io, collections::HashMap};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use blake2::{Digest, Blake2s256};
use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use dkg::{Participant, ThresholdKeys, evrf::*};

use serai_validator_sets_primitives::Session;
use messages::key_gen::*;

use serai_db::{Get, DbTxn};

mod generators;
use generators::generators;

mod db;
use db::{Params, Participations, KeyGenDb};

/// Parameters for a key generation.
pub trait KeyGenParams {
  /// The ID for this instantiation.
  const ID: &'static str;

  /// The curve used for the external network.
  type ExternalNetworkCurve: EvrfCurve<
    EmbeddedCurve: Ciphersuite<
      G: ec_divisors::DivisorCurve<FieldElement = <Self::ExternalNetworkCurve as Ciphersuite>::F>,
    >,
  >;

  /// Tweaks keys as necessary/beneficial.
  fn tweak_keys(keys: &mut ThresholdKeys<Self::ExternalNetworkCurve>);

  /// Encode keys as optimal.
  ///
  /// A default implementation is provided which calls the traditional `to_bytes`.
  fn encode_key(key: <Self::ExternalNetworkCurve as Ciphersuite>::G) -> Vec<u8> {
    key.to_bytes().as_ref().to_vec()
  }

  /// Decode keys from their optimal encoding.
  ///
  /// A default implementation is provided which calls the traditional `from_bytes`.
  fn decode_key(mut key: &[u8]) -> Option<<Self::ExternalNetworkCurve as Ciphersuite>::G> {
    let res = <Self::ExternalNetworkCurve as Ciphersuite>::read_G(&mut key).ok()?;
    if !key.is_empty() {
      None?;
    }
    Some(res)
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

/// An instance of the Serai key generation protocol.
#[derive(Debug)]
pub struct KeyGen<P: KeyGenParams> {
  substrate_evrf_private_key:
    Zeroizing<<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
  network_evrf_private_key:
    Zeroizing<<<P::ExternalNetworkCurve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
}

impl<P: KeyGenParams> KeyGen<P> {
  /// Create a new key generation instance.
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    substrate_evrf_private_key: Zeroizing<
      <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F,
    >,
    network_evrf_private_key: Zeroizing<
      <<P::ExternalNetworkCurve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F,
    >,
  ) -> KeyGen<P> {
    KeyGen { substrate_evrf_private_key, network_evrf_private_key }
  }

  /// Fetch the key shares for a specific session.
  #[allow(clippy::type_complexity)]
  pub fn key_shares(
    getter: &impl Get,
    session: Session,
  ) -> Option<(Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<P::ExternalNetworkCurve>>)> {
    // This is safe, despite not having a txn, since it's a static value
    // It doesn't change over time/in relation to other operations
    // It is solely set or unset
    KeyGenDb::<P>::key_shares(getter, session)
  }

  /// Handle a message from the coordinator.
  pub fn handle(&mut self, txn: &mut impl DbTxn, msg: CoordinatorMessage) -> Vec<ProcessorMessage> {
    const SUBSTRATE_KEY_CONTEXT: &[u8] = b"substrate";
    const NETWORK_KEY_CONTEXT: &[u8] = b"network";
    fn context<P: KeyGenParams>(session: Session, key_context: &[u8]) -> [u8; 32] {
      // TODO2: Also embed the chain ID/genesis block
      let mut transcript = RecommendedTranscript::new(b"Serai eVRF Key Gen");
      transcript.append_message(b"network", P::ID.as_bytes());
      transcript.append_message(b"session", session.0.to_le_bytes());
      transcript.append_message(b"key", key_context);
      (&(&transcript.challenge(b"context"))[.. 32]).try_into().unwrap()
    }

    match msg {
      CoordinatorMessage::GenerateKey { session, threshold, evrf_public_keys } => {
        log::info!("generating new key, session: {session:?}");

        // Unzip the vector of eVRF keys
        let substrate_evrf_public_keys =
          evrf_public_keys.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let (substrate_evrf_public_keys, mut faulty) =
          coerce_keys::<Ristretto>(&substrate_evrf_public_keys);

        let network_evrf_public_keys =
          evrf_public_keys.into_iter().map(|(_, key)| key).collect::<Vec<_>>();
        let (network_evrf_public_keys, additional_faulty) =
          coerce_keys::<P::ExternalNetworkCurve>(&network_evrf_public_keys);
        faulty.extend(additional_faulty);

        // Participate for both Substrate and the network
        fn participate<C: EvrfCurve>(
          context: [u8; 32],
          threshold: u16,
          evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
          evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
          output: &mut impl io::Write,
        ) {
          let participation = EvrfDkg::<C>::participate(
            &mut OsRng,
            generators(),
            context,
            threshold,
            evrf_public_keys,
            evrf_private_key,
          );
          participation.unwrap().write(output).unwrap();
        }

        let mut participation = Vec::with_capacity(2048);
        participate::<Ristretto>(
          context::<P>(session, SUBSTRATE_KEY_CONTEXT),
          threshold,
          &substrate_evrf_public_keys,
          &self.substrate_evrf_private_key,
          &mut participation,
        );
        participate::<P::ExternalNetworkCurve>(
          context::<P>(session, NETWORK_KEY_CONTEXT),
          threshold,
          &network_evrf_public_keys,
          &self.network_evrf_private_key,
          &mut participation,
        );

        // Save the params
        KeyGenDb::<P>::set_params(
          txn,
          session,
          Params {
            t: threshold,
            n: substrate_evrf_public_keys
              .len()
              .try_into()
              .expect("amount of keys exceeded the amount allowed during a DKG"),
            substrate_evrf_public_keys,
            network_evrf_public_keys,
          },
        );

        // Send back our Participation and all faulty parties
        let mut res = Vec::with_capacity(faulty.len() + 1);
        faulty.sort_unstable();
        for faulty in faulty {
          res.push(ProcessorMessage::Blame { session, participant: faulty });
        }
        res.push(ProcessorMessage::Participation { session, participation });

        res
      }

      CoordinatorMessage::Participation { session, participant, participation } => {
        log::debug!("received participation from {:?} for {:?}", participant, session);

        let Params { t: threshold, n, substrate_evrf_public_keys, network_evrf_public_keys } =
          KeyGenDb::<P>::params(txn, session).unwrap();

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
            let Ok(network_participation) =
              Participation::<P::ExternalNetworkCurve>::read(&mut participation, n)
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
            if Self::key_shares(txn, session).is_some() {
              log::debug!("already finished generating a key for {:?}", session);

              match EvrfDkg::<Ristretto>::verify(
                &mut OsRng,
                generators(),
                context::<P>(session, SUBSTRATE_KEY_CONTEXT),
                threshold,
                &substrate_evrf_public_keys,
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

              match EvrfDkg::<P::ExternalNetworkCurve>::verify(
                &mut OsRng,
                generators(),
                context::<P>(session, NETWORK_KEY_CONTEXT),
                threshold,
                &network_evrf_public_keys,
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
          KeyGenDb::<P>::participations(txn, session).map_or_else(
            || (HashMap::with_capacity(1), HashMap::with_capacity(1)),
            |p| (p.substrate_participations, p.network_participations),
          );
        assert!(
          substrate_participations.insert(participant, substrate_participation).is_none() &&
            network_participations.insert(participant, network_participation).is_none(),
          "received participation for someone multiple times"
        );
        KeyGenDb::<P>::set_participations(
          txn,
          session,
          &Participations {
            substrate_participations: substrate_participations.clone(),
            network_participations: network_participations.clone(),
          },
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
        fn verify_dkg<P: KeyGenParams, C: EvrfCurve>(
          txn: &mut impl DbTxn,
          session: Session,
          true_if_substrate_false_if_network: bool,
          threshold: u16,
          evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
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
            context::<P>(
              session,
              if true_if_substrate_false_if_network {
                SUBSTRATE_KEY_CONTEXT
              } else {
                NETWORK_KEY_CONTEXT
              },
            ),
            threshold,
            evrf_public_keys,
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
              KeyGenDb::<P>::set_participations(
                txn,
                session,
                &Participations {
                  substrate_participations: substrate_participations.clone(),
                  network_participations: network_participations.clone(),
                },
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

        let substrate_dkg = match verify_dkg::<P, Ristretto>(
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

        let network_dkg = match verify_dkg::<P, P::ExternalNetworkCurve>(
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
          P::tweak_keys(network_keys);
        }
        KeyGenDb::<P>::set_key_shares(txn, session, &substrate_keys, &network_keys);

        log::info!("generated key, session: {session:?}");

        // Since no one we verified was invalid, and we had the threshold, yield the new keys
        vec![ProcessorMessage::GeneratedKeyPair {
          session,
          substrate_key: substrate_keys[0].group_key().to_bytes(),
          network_key: P::encode_key(network_keys[0].group_key()),
        }]
      }
    }
  }
}
