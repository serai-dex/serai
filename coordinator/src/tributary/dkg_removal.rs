use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use frost::{
  FrostError,
  dkg::{Participant, musig::musig},
  sign::*,
};
use frost_schnorrkel::Schnorrkel;

use serai_client::{
  Public,
  validator_sets::primitives::{musig_context, remove_participant_message},
};

use crate::tributary::TributarySpec;

/*
  The following is a clone of DkgConfirmer modified for DKG removals.

  The notable difference is this uses a MuSig key of the first `t` participants to respond with
  preprocesses, not all `n` participants.

  TODO: Exact same commentary on seeded RNGs. The following can drop its seeded RNG if cached
  preprocesses are used to carry the preprocess between machines
*/
pub(crate) struct DkgRemoval;
impl DkgRemoval {
  // Convert the passed in HashMap, which uses the validators' start index for their `s` threshold
  // shares, to the indexes needed for MuSig
  fn from_threshold_i_to_musig_i(
    mut old_map: HashMap<[u8; 32], Vec<u8>>,
  ) -> HashMap<Participant, Vec<u8>> {
    let mut new_map = HashMap::new();
    let mut participating = old_map.keys().cloned().collect::<Vec<_>>();
    participating.sort();
    for (i, participating) in participating.into_iter().enumerate() {
      new_map.insert(
        Participant::new(u16::try_from(i + 1).unwrap()).unwrap(),
        old_map.remove(&participating).unwrap(),
      );
    }
    new_map
  }

  fn preprocess_rng(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
  ) -> ChaCha20Rng {
    ChaCha20Rng::from_seed({
      let mut entropy_transcript = RecommendedTranscript::new(b"DkgRemoval Entropy");
      entropy_transcript.append_message(b"spec", spec.serialize());
      entropy_transcript.append_message(b"key", Zeroizing::new(key.to_bytes()));
      entropy_transcript.append_message(b"attempt", attempt.to_le_bytes());
      Zeroizing::new(entropy_transcript).rng_seed(b"preprocess")
    })
  }

  fn preprocess_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    participants: Option<&[<Ristretto as Ciphersuite>::G]>,
  ) -> (Option<AlgorithmSignMachine<Ristretto, Schnorrkel>>, [u8; 64]) {
    // TODO: Diversify this among DkgConfirmer/DkgRemoval?
    let context = musig_context(spec.set());

    let (_, preprocess) = AlgorithmMachine::new(
      Schnorrkel::new(b"substrate"),
      // Preprocess with our key alone as we don't know the signing set yet
      musig(&context, key, &[<Ristretto as Ciphersuite>::G::generator() * key.deref()])
        .expect("couldn't get the MuSig key of our key alone")
        .into(),
    )
    .preprocess(&mut Self::preprocess_rng(spec, key, attempt));

    let machine = if let Some(participants) = participants {
      let (machine, actual_preprocess) = AlgorithmMachine::new(
        Schnorrkel::new(b"substrate"),
        // Preprocess with our key alone as we don't know the signing set yet
        musig(&context, key, participants)
          .expect(
            "couldn't create a MuSig key for the DKG removal we're supposedly participating in",
          )
          .into(),
      )
      .preprocess(&mut Self::preprocess_rng(spec, key, attempt));
      // Doesn't use assert_eq due to lack of Debug
      assert!(preprocess == actual_preprocess);
      Some(machine)
    } else {
      None
    };

    (machine, preprocess.serialize().try_into().unwrap())
  }
  // Get the preprocess for this confirmation.
  pub(crate) fn preprocess(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
  ) -> [u8; 64] {
    Self::preprocess_internal(spec, key, attempt, None).1
  }

  fn share_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    mut preprocesses: HashMap<Participant, Vec<u8>>,
    removed: [u8; 32],
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    // TODO: Remove this ugly blob
    let preprocesses = {
      let mut preprocesses_participants = preprocesses.keys().cloned().collect::<Vec<_>>();
      preprocesses_participants.sort();
      let mut actual_keys = vec![];
      let spec_validators = spec.validators();
      for participant in &preprocesses_participants {
        for (validator, _) in &spec_validators {
          if participant == &spec.i(*validator).unwrap().start {
            actual_keys.push(*validator);
          }
        }
      }

      let mut new_preprocesses = HashMap::new();
      for (participant, actual_key) in
        preprocesses_participants.into_iter().zip(actual_keys.into_iter())
      {
        new_preprocesses.insert(actual_key, preprocesses.remove(&participant).unwrap());
      }
      new_preprocesses
    };

    let participants = preprocesses.keys().cloned().collect::<Vec<_>>();
    let preprocesses = Self::from_threshold_i_to_musig_i(
      preprocesses.into_iter().map(|(key, preprocess)| (key.to_bytes(), preprocess)).collect(),
    );
    let machine = Self::preprocess_internal(spec, key, attempt, Some(&participants)).0.unwrap();
    let preprocesses = preprocesses
      .into_iter()
      .map(|(p, preprocess)| {
        machine
          .read_preprocess(&mut preprocess.as_slice())
          .map(|preprocess| (p, preprocess))
          .map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let (machine, share) = machine
      .sign(preprocesses, &remove_participant_message(&spec.set(), Public(removed)))
      .map_err(|e| match e {
        FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
        FrostError::InvalidParticipant(_, _) |
        FrostError::InvalidSigningSet(_) |
        FrostError::InvalidParticipantQuantity(_, _) |
        FrostError::DuplicatedParticipant(_) |
        FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
        FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
      })?;

    Ok((machine, share.serialize().try_into().unwrap()))
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  pub(crate) fn share(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    preprocesses: HashMap<Participant, Vec<u8>>,
    removed: [u8; 32],
  ) -> Result<[u8; 32], Participant> {
    Self::share_internal(spec, key, attempt, preprocesses, removed).map(|(_, share)| share)
  }

  pub(crate) fn complete(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    preprocesses: HashMap<Participant, Vec<u8>>,
    removed: [u8; 32],
    mut shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<(Vec<Public>, [u8; 64]), Participant> {
    // TODO: Remove this ugly blob
    let shares = {
      let mut shares_participants = shares.keys().cloned().collect::<Vec<_>>();
      shares_participants.sort();
      let mut actual_keys = vec![];
      let spec_validators = spec.validators();
      for participant in &shares_participants {
        for (validator, _) in &spec_validators {
          if participant == &spec.i(*validator).unwrap().start {
            actual_keys.push(*validator);
          }
        }
      }

      let mut new_shares = HashMap::new();
      for (participant, actual_key) in shares_participants.into_iter().zip(actual_keys.into_iter())
      {
        new_shares.insert(actual_key.to_bytes(), shares.remove(&participant).unwrap());
      }
      new_shares
    };

    let mut signers = shares.keys().cloned().map(Public).collect::<Vec<_>>();
    signers.sort();

    let machine = Self::share_internal(spec, key, attempt, preprocesses, removed)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

    let shares = Self::from_threshold_i_to_musig_i(shares)
      .into_iter()
      .map(|(p, share)| {
        machine.read_share(&mut share.as_slice()).map(|share| (p, share)).map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let signature = machine.complete(shares).map_err(|e| match e {
      FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
      FrostError::InvalidParticipant(_, _) |
      FrostError::InvalidSigningSet(_) |
      FrostError::InvalidParticipantQuantity(_, _) |
      FrostError::DuplicatedParticipant(_) |
      FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
      FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
    })?;

    Ok((signers, signature.to_bytes()))
  }
}
