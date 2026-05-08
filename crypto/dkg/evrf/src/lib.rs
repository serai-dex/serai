#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

use core::ops::Deref as _;
use std_shims::{
  prelude::*,
  io::{self, Read, Write},
  collections::{HashSet, HashMap},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize as _, Zeroizing};

use blake2::{Digest as _, Blake2s256};
use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  },
  WrappedGroup, GroupIo,
};
use multiexp::multiexp_vartime;

use generalized_bulletproofs::arithmetic_circuit_proof::*;
use ec_divisors::DivisorCurve as _;

pub use dkg::*;

mod utils;
pub(crate) use utils::*;

mod curves;
pub use curves::*;

mod proof;
use proof::*;

mod shares;
use shares::EncryptedSecretShare;

#[cfg(test)]
extern crate std;

/// Participation in the DKG.
///
/// `Participation` is meant to be broadcast to all other participants over an authenticated,
/// reliable broadcast channel. For consistent parameters, any valid participation from a
/// participant will encode the same polynomial however (even if the participations serialize
/// differently).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Participation<C: Curves> {
  proof: Vec<u8>,
  /// These are `(to, share)`.
  encrypted_secret_shares: HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>,
}

impl<C: Curves> Participation<C> {
  /// Read a participation of length variable to the `t, n` parameters.
  pub fn read<R: Read>(reader: &mut R, t: u16, n: u16) -> io::Result<Self> {
    let mut proof = vec![0; Proof::<C>::transcript_len(t.into(), n.into())];
    reader.read_exact(&mut proof)?;

    let mut encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
    for i in Participant::iter().take(usize::from(n)) {
      assert!(encrypted_secret_shares
        .insert(i, <C::ToweringCurve as GroupIo>::read_F(reader)?)
        .is_none());
    }

    Ok(Self { proof, encrypted_secret_shares })
  }

  /// Write the participation.
  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.proof)?;
    for i in Participant::iter().take(self.encrypted_secret_shares.len()) {
      writer.write_all(self.encrypted_secret_shares[&i].to_repr().as_ref())?;
    }
    Ok(())
  }
}

/// Errors from the eVRF DKG.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum Error {
  /// Too many participants were provided.
  #[error("{provided} participants provided, exceeding the limit of u16::MAX")]
  TooManyParticipants {
    /// The amount of provided participants.
    provided: usize,
  },

  /// The threshold exceeded the amount of participants.
  #[error("invalid threshold (max {n}, got {t})")]
  InvalidThreshold {
    /// The specified threshold.
    t: u16,
    /// The specified total amount of participants.
    n: u16,
  },

  /// A participant's public key was the identity point.
  #[error("a public key was the identity point")]
  PublicKeyWasIdentity,

  /// Participating in a DKG we aren't present in.
  #[error("participating in a DKG we aren't a participant in")]
  NotAParticipant,

  /// A participant which doesn't exist provided a participation.
  #[error("a participant with an unrecognized ID participated")]
  NonExistentParticipant,

  /// Insufficient amount of generators for this DKG.
  #[error("the passed in generators ({provided}) weren't enough for this DKG (needed {required})")]
  NotEnoughGenerators {
    /// The amount of generators provided.
    provided: usize,
    /// The amount of generators required.
    required: usize,
  },
}

/// The result from calling `Dkg::verify`.
pub enum VerifyResult<C: Curves> {
  /// The DKG participations were valid.
  Valid(Dkg<C>),
  /// The DKG participants were invalid, identifying the faulty participants.
  Invalid(Vec<Participant>),
  /// Not enough participations were provided, yet no provided participations were faulty.
  NotEnoughParticipants,
}

/// The representation of a completed DKG.
pub struct Dkg<C: Curves> {
  t: u16,
  n: u16,
  evrf_public_keys: Vec<<C::EmbeddedCurve as WrappedGroup>::G>,
  verification_shares: HashMap<Participant, <C::ToweringCurve as WrappedGroup>::G>,
  /// These are `(from, (to, share))`.
  encrypted_secret_shares: HashMap<Participant, HashMap<Participant, EncryptedSecretShare<C>>>,
}

impl<C: Curves> Dkg<C> {
  // Form the initial transcript for the proofs.
  fn initial_transcript(
    invocation: [u8; 32],
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    t: u16,
    n: u16,
  ) -> Blake2s256 {
    let mut transcript = Blake2s256::new();
    transcript.update(invocation);
    transcript.update(n.to_le_bytes());
    for key in evrf_public_keys {
      transcript.update(key.to_bytes().as_ref());
    }
    transcript.update(t.to_le_bytes());
    transcript
  }

  /// Participate in performing the DKG for the specified parameters.
  ///
  /// The context MUST be unique across invocations. Reuse of context will lead to sharing
  /// prior-shared secrets again.
  ///
  /// `evrf_public_keys` is the eVRF public keys of the participants in the DKG protocol who are
  /// eligible to perform a secret-sharing and will also receive shares.
  pub fn participate(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as WrappedGroup>::F>,
  ) -> Result<Participation<C>, Error> {
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else {
      Err(Error::TooManyParticipants { provided: evrf_public_keys.len() })?
    };
    if (t == 0) || (t > n) {
      Err(Error::InvalidThreshold { t, n })?;
    }
    if evrf_public_keys.iter().any(|key| bool::from(key.is_identity())) {
      Err(Error::PublicKeyWasIdentity)?;
    }
    // This also ensures the private key is not 0, due to the prior check the identity point wasn't
    // present
    let evrf_public_key =
      <C::EmbeddedCurve as WrappedGroup>::generator() * evrf_private_key.deref();
    if !evrf_public_keys.contains(&evrf_public_key) {
      Err(Error::NotAParticipant)?;
    }

    let mut transcript = Self::initial_transcript(context, evrf_public_keys, t, n);
    // Bind to the participant
    transcript.update(evrf_public_key.to_bytes());

    let ProveResult { coefficients, encryption_keys, proof } = match Proof::<C>::prove(
      rng,
      &generators.0,
      transcript.finalize().into(),
      usize::from(t),
      evrf_public_keys,
      evrf_private_key,
    ) {
      Ok(res) => res,
      Err(AcProveError::IncorrectAmountOfGenerators) => Err(Error::NotEnoughGenerators {
        provided: generators.0.g_bold_slice().len(),
        required: Proof::<C>::generators_to_use(usize::from(t), evrf_public_keys.len()),
      })?,
      Err(AcProveError::InconsistentWitness) => panic!("failed to prove for the eVRF proof"),
    };

    let mut encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
    for (l, encryption_key) in Participant::iter().take(usize::from(n)).zip(encryption_keys) {
      let share = polynomial::<<C::ToweringCurve as WrappedGroup>::F>(&coefficients, l);
      assert!(encrypted_secret_shares.insert(l, *share + *encryption_key).is_none());
    }

    Ok(Participation { proof, encrypted_secret_shares })
  }

  #[expect(clippy::too_many_arguments)]
  fn queue_single_proof_for_batch_verification(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    evrf_verifier: &mut generalized_bulletproofs::BatchVerifier<C::ToweringCurve>,
    transcript: &Blake2s256,
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    i: Participant,
    participation: &Participation<C>,
  ) -> Result<Verified<C>, ()> {
    let evrf_public_key = evrf_public_keys[usize::from(u16::from(i)) - 1];

    let mut per_proof_transcript = transcript.clone();
    per_proof_transcript.update(evrf_public_key.to_bytes());

    Proof::<C>::verify(
      rng,
      &generators.0,
      evrf_verifier,
      per_proof_transcript.finalize().into(),
      usize::from(t),
      evrf_public_keys,
      evrf_public_key,
      &participation.proof,
    )
  }

  #[expect(clippy::too_many_arguments, clippy::type_complexity)]
  fn queue_for_batch_verification(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    n: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    participations: &HashMap<Participant, Participation<C>>,
    potentially_valid: &mut HashMap<
      Participant,
      (HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>, Verified<C>),
    >,
    faulty: &mut HashSet<Participant>,
  ) -> generalized_bulletproofs::BatchVerifier<C::ToweringCurve> {
    let transcript = Self::initial_transcript(context, evrf_public_keys, t, n);

    let mut evrf_verifier = generalized_bulletproofs::Generators::batch_verifier();
    for (i, participation) in participations {
      // Clone the verifier so if this proof is faulty, it doesn't corrupt the verifier
      let mut verifier_clone = evrf_verifier.clone();
      let Ok(data) = Self::queue_single_proof_for_batch_verification(
        rng,
        generators,
        &mut verifier_clone,
        &transcript,
        t,
        evrf_public_keys,
        *i,
        participation,
      ) else {
        assert!(faulty.insert(*i));
        continue;
      };
      evrf_verifier = verifier_clone;

      assert!(potentially_valid
        .insert(*i, (participation.encrypted_secret_shares.clone(), data))
        .is_none());
    }
    debug_assert_eq!(potentially_valid.len() + faulty.len(), participations.len());

    evrf_verifier
  }

  #[expect(clippy::too_many_arguments, clippy::type_complexity)]
  fn verify_structurally_valid_proofs(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    n: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    participations: &HashMap<Participant, Participation<C>>,
    potentially_valid: &mut HashMap<
      Participant,
      (HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>, Verified<C>),
    >,
    faulty: &mut HashSet<Participant>,
    evrf_verifier: generalized_bulletproofs::BatchVerifier<C::ToweringCurve>,
  ) {
    // Perform the batch verification of the eVRFs
    if generators.0.verify(evrf_verifier) {
      return;
    }

    // If the batch failed, verify them each individually
    #[cfg(debug_assertions)]
    let faulty_len_at_start = faulty.len();
    let transcript = Self::initial_transcript(context, evrf_public_keys, t, n);
    for (i, participation) in participations {
      if faulty.contains(i) {
        continue;
      }

      let mut evrf_verifier = generalized_bulletproofs::Generators::batch_verifier();
      Self::queue_single_proof_for_batch_verification(
        rng,
        generators,
        &mut evrf_verifier,
        &transcript,
        t,
        evrf_public_keys,
        *i,
        participation,
      )
      .expect("evrf failed structural checks yet prover wasn't prior marked faulty");
      if !generators.0.verify(evrf_verifier) {
        assert!(potentially_valid.remove(i).is_some());
        assert!(faulty.insert(*i));
      }
    }
    #[cfg(debug_assertions)]
    {
      debug_assert!(faulty_len_at_start < faulty.len());
    }
  }

  fn participating_weight(
    participating: impl Iterator<Item = Participant>,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
  ) -> usize {
    let mut participating_weight = 0;
    let mut evrf_public_keys_mut = evrf_public_keys.to_vec();
    for i in participating {
      let evrf_public_key = evrf_public_keys[usize::from(u16::from(i)) - 1];

      /*
        Remove this key from the `Vec` to prevent double-counting.

        Double-counting would be a risk if multiple participants shared an eVRF public key and
        participated. This code does still allow such participants (in order to let participants
        be weighted), and any one of them participating will count as all participating. This is
        fine as any one such participant will be able to decrypt the shares for themselves and
        all other participants with the same key, so this is still a key generated by an amount
        of participants who could simply reconstruct the key.
      */
      let start_len = evrf_public_keys_mut.len();
      evrf_public_keys_mut.retain(|key| *key != evrf_public_key);
      let end_len = evrf_public_keys_mut.len();
      let count = start_len - end_len;

      participating_weight += count;
    }
    participating_weight
  }

  /// Check if a batch of `Participation`s are valid.
  ///
  /// If any `Participation` is invalid, the list of all invalid participants will be returned.
  /// If all `Participation`s are valid and there's at least `t`, an instance of this struct
  /// (usable to obtain a threshold share of generated key) is returned. If all are valid and
  /// there's not at least `t`, `VerifyResult::NotEnoughParticipants` is returned.
  ///
  /// This DKG is unbiased if all `n` people participate. This DKG is biased if only a threshold
  /// participate.
  pub fn verify(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    participations: &HashMap<Participant, Participation<C>>,
  ) -> Result<VerifyResult<C>, Error> {
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else {
      Err(Error::TooManyParticipants { provided: evrf_public_keys.len() })?
    };
    if (t == 0) || (t > n) {
      Err(Error::InvalidThreshold { t, n })?;
    }
    if evrf_public_keys.iter().any(|key| bool::from(key.is_identity())) {
      Err(Error::PublicKeyWasIdentity)?;
    }
    for i in participations.keys() {
      if u16::from(*i) > n {
        Err(Error::NonExistentParticipant)?;
      }
    }

    let mut potentially_valid = HashMap::with_capacity(participations.len());
    let mut faulty = HashSet::new();

    let evrf_verifier = Self::queue_for_batch_verification(
      rng,
      generators,
      context,
      t,
      n,
      evrf_public_keys,
      participations,
      &mut potentially_valid,
      &mut faulty,
    );
    debug_assert_eq!(potentially_valid.len() + faulty.len(), participations.len());
    Self::verify_structurally_valid_proofs(
      rng,
      generators,
      context,
      t,
      n,
      evrf_public_keys,
      participations,
      &mut potentially_valid,
      &mut faulty,
      evrf_verifier,
    );
    debug_assert_eq!(potentially_valid.len() + faulty.len(), participations.len());
    let shares = shares::verify::<C>(
      rng,
      generators,
      t,
      n,
      evrf_public_keys,
      &mut potentially_valid,
      &mut faulty,
    );
    let valid = potentially_valid;
    debug_assert_eq!(valid.len() + faulty.len(), participations.len());

    let mut faulty = faulty.into_iter().collect::<Vec<_>>();
    if !faulty.is_empty() {
      faulty.sort_unstable();
      return Ok(VerifyResult::Invalid(faulty));
    }

    /*
      We check at least `t` key shares of people have participated in contributing entropy. Since
      the key shares of the participants exceed `t`, meaning if they're malicious they can
      reconstruct the key regardless, this is safe to the threshold.
    */
    if Self::participating_weight(valid.keys().copied(), evrf_public_keys) < usize::from(t) {
      return Ok(VerifyResult::NotEnoughParticipants);
    }

    let shares::Verified { verification_shares, encrypted_secret_shares } = shares.expect(
      "no one was faulty, participants exceeded the threshold, yet verified shares were `None`",
    );

    // As we now have `>= t` participations, output the result
    Ok(VerifyResult::Valid(Dkg {
      t,
      n,
      evrf_public_keys: evrf_public_keys.to_vec(),
      verification_shares,
      encrypted_secret_shares,
    }))
  }

  /// Retrieve keys from a successful DKG.
  ///
  /// This will return _all_ keys belonging to the participant.
  pub fn keys(
    &self,
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as WrappedGroup>::F>,
  ) -> Vec<ThresholdKeys<C::ToweringCurve>> {
    let evrf_public_key =
      <C::EmbeddedCurve as WrappedGroup>::generator() * evrf_private_key.deref();

    // Identify all `Participant`s which belong to this key
    let mut is = Vec::with_capacity(1);
    for (i, evrf_key) in Participant::iter().zip(self.evrf_public_keys.iter()) {
      if *evrf_key == evrf_public_key {
        is.push(i);
      }
    }

    let mut res = Vec::with_capacity(is.len());
    for i in is {
      // Decrypt the secret share
      let mut secret_share = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
      // The key is `from`, which is irrelevant here, hence why we solely iterate the values
      for shares in self.encrypted_secret_shares.values() {
        *secret_share += shares[&i].decrypt(evrf_private_key).deref();
      }
      debug_assert_eq!(
        self.verification_shares[&i],
        <C::ToweringCurve as WrappedGroup>::generator() * secret_share.deref()
      );

      // Push it onto the result
      res.push(
        ThresholdKeys::new(
          ThresholdParams::new(self.t, self.n, i).unwrap(),
          Interpolation::Lagrange,
          secret_share,
          self.verification_shares.clone(),
        )
        .unwrap(),
      );
    }

    res
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn too_many_participants() {
    use rand_core::OsRng;

    let generators = Generators::<Ed25519>::new(1, 1);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let pub_keys =
      vec![<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key; 1 << 16];

    assert_eq!(
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, 1, &pub_keys, &priv_key)
        .map(|_| ())
        .unwrap_err(),
      Error::TooManyParticipants { provided: 1 << 16 }
    );

    assert_eq!(
      Dkg::<Ed25519>::verify(&mut OsRng, &generators, context, 1, &pub_keys, &HashMap::new())
        .map(|_| ())
        .unwrap_err(),
      Error::TooManyParticipants { provided: 1 << 16 }
    );
  }

  #[test]
  fn invalid_threshold() {
    use rand_core::OsRng;

    let generators = Generators::<Ed25519>::new(1, 1);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let pub_keys =
      vec![<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key];

    assert_eq!(
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, 2, &pub_keys, &priv_key)
        .map(|_| ())
        .unwrap_err(),
      Error::InvalidThreshold { t: 2, n: 1 }
    );

    assert_eq!(
      Dkg::<Ed25519>::verify(&mut OsRng, &generators, context, 2, &pub_keys, &HashMap::new())
        .map(|_| ())
        .unwrap_err(),
      Error::InvalidThreshold { t: 2, n: 1 }
    );
  }

  #[test]
  fn identity() {
    use rand_core::OsRng;

    let generators = Generators::<Ed25519>::new(1, 1);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let pub_keys = vec![
      <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key,
      <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::G::identity(),
    ];

    assert_eq!(
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, 1, &pub_keys, &priv_key)
        .map(|_| ())
        .unwrap_err(),
      Error::PublicKeyWasIdentity
    );

    assert_eq!(
      Dkg::<Ed25519>::verify(&mut OsRng, &generators, context, 1, &pub_keys, &HashMap::new())
        .map(|_| ())
        .unwrap_err(),
      Error::PublicKeyWasIdentity
    );
  }

  #[test]
  fn not_a_participant() {
    use rand_core::OsRng;

    let generators = Generators::<Ed25519>::new(1, 1);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let pub_keys = vec![<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator()];

    assert_eq!(
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, 1, &pub_keys, &priv_key)
        .map(|_| ())
        .unwrap_err(),
      Error::NotAParticipant
    );
  }

  #[test]
  fn non_existent_participant() {
    use rand_core::OsRng;

    let generators = Generators::<Ed25519>::new(1, 1);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let pub_keys =
      vec![<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key];

    let participation =
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, 1, &pub_keys, &priv_key)
        .unwrap();

    assert_eq!(
      Dkg::<Ed25519>::verify(
        &mut OsRng,
        &generators,
        context,
        1,
        &pub_keys,
        &HashMap::from([(Participant::new(2).unwrap(), participation)]),
      )
      .map(|_| ())
      .unwrap_err(),
      Error::NonExistentParticipant
    );
  }

  #[test]
  fn not_enough_participants() {
    use rand_core::OsRng;
    use rand::seq::SliceRandom as _;

    let threshold = 3;
    let participants = 4;
    let generators = Generators::<Ed25519>::new(threshold, participants);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let mut priv_keys = vec![];
    let mut pub_keys = vec![];
    for i in 0 .. participants {
      let priv_key =
        Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
      pub_keys.push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key);
      priv_keys.push((Participant::new(1 + i).unwrap(), priv_key));
    }
    // Shuffle the private keys so we iterate over a random subset of them
    priv_keys.shuffle(&mut OsRng);

    let mut participations = HashMap::new();
    for (i, priv_key) in priv_keys.iter().take(usize::from(threshold)) {
      // As this has yet to reach the threshold, this should yield `NotEnoughParticipants`
      assert!(matches!(
        Dkg::<Ed25519>::verify(
          &mut OsRng,
          &generators,
          context,
          threshold,
          &pub_keys,
          &participations,
        )
        .unwrap(),
        VerifyResult::NotEnoughParticipants
      ));

      let participation = Dkg::<Ed25519>::participate(
        &mut OsRng,
        &generators,
        context,
        threshold,
        &pub_keys,
        priv_key,
      )
      .unwrap();

      assert!(participations.insert(*i, participation).is_none());
    }

    // Now that it's hit the expected amount of participants, it should `Valid`
    assert!(matches!(
      Dkg::<Ed25519>::verify(
        &mut OsRng,
        &generators,
        context,
        threshold,
        &pub_keys,
        &participations
      )
      .unwrap(),
      VerifyResult::Valid(_)
    ));
  }

  #[test]
  fn queue_for_batch_verification() {
    use rand_core::OsRng;

    let threshold = 3;
    let participants = 4;
    let generators = Generators::<Ed25519>::new(threshold, participants);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let mut priv_keys = vec![];
    let mut pub_keys = vec![];
    for i in 0 .. participants {
      let priv_key =
        Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
      pub_keys.push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key);
      priv_keys.push((Participant::new(1 + i).unwrap(), priv_key));
    }

    let priv_key = &priv_keys[0];
    let participation = Dkg::<Ed25519>::participate(
      &mut OsRng,
      &generators,
      context,
      threshold,
      &pub_keys,
      &priv_key.1,
    )
    .unwrap();
    let participation = {
      let mut participation_bytes = vec![];
      participation.write(&mut participation_bytes).unwrap();
      // Malleate the proof in a way it'll fail to even be queued for batch verification
      let start_of_last_element_in_proof =
        participation_bytes.len() - ((1 + usize::from(participants)) * 32);
      for byte in &mut participation_bytes
        [start_of_last_element_in_proof .. (start_of_last_element_in_proof + 32)]
      {
        *byte = 0xff;
      }
      Participation::<Ed25519>::read(&mut participation_bytes.as_slice(), threshold, participants)
        .unwrap()
    };

    let mut potentially_valid = HashMap::new();
    let mut faulty = HashSet::new();
    let generalized_bulletproofs::BatchVerifier { g, h, g_bold, h_bold, h_sum, additional } =
      Dkg::<Ed25519>::queue_for_batch_verification(
        &mut OsRng,
        &generators,
        context,
        threshold,
        pub_keys.len().try_into().unwrap(),
        &pub_keys,
        &HashMap::from([(priv_key.0, participation)]),
        &mut potentially_valid,
        &mut faulty,
      );
    assert!(potentially_valid.is_empty());
    assert_eq!(faulty, HashSet::from([priv_key.0]));
    // The `BatchVerifier` should not have had the faulty proof accumulated
    assert!(bool::from(g.is_zero()));
    assert!(bool::from(h.is_zero()));
    assert!(g_bold.is_empty());
    assert!(h_bold.is_empty());
    assert!(h_sum.is_empty());
    assert!(additional.is_empty());
  }

  #[test]
  fn verify_structurally_valid_proofs() {
    use rand_core::OsRng;

    let threshold = 3;
    let participants = 4;
    let generators = Generators::<Ed25519>::new(threshold, participants);

    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let mut priv_keys = vec![];
    let mut pub_keys = vec![];
    for i in 0 .. participants {
      let priv_key =
        Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
      pub_keys.push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key);
      priv_keys.push((Participant::new(1 + i).unwrap(), priv_key));
    }

    let mut participations = HashMap::new();
    for (i, priv_key) in priv_keys[.. 2].iter().enumerate() {
      let mut participation = Dkg::<Ed25519>::participate(
        &mut OsRng,
        &generators,
        context,
        threshold,
        &pub_keys,
        &priv_key.1,
      )
      .unwrap();

      if i == 0 {
        participation = {
          let mut participation_bytes = vec![];
          participation.write(&mut participation_bytes).unwrap();
          // Malleate the proof in a way it'll be queued for batch verification but will be invalid
          let start_of_last_element_in_proof =
            participation_bytes.len() - ((1 + usize::from(participants)) * 32);
          participation_bytes[start_of_last_element_in_proof] ^= 1;
          Participation::<Ed25519>::read(
            &mut participation_bytes.as_slice(),
            threshold,
            participants,
          )
          .unwrap()
        };
      }

      assert!(participations.insert(priv_key.0, participation).is_none());
    }

    let mut potentially_valid = HashMap::new();
    let mut faulty = HashSet::new();
    let verifier = Dkg::<Ed25519>::queue_for_batch_verification(
      &mut OsRng,
      &generators,
      context,
      threshold,
      pub_keys.len().try_into().unwrap(),
      &pub_keys,
      &participations,
      &mut potentially_valid,
      &mut faulty,
    );
    assert_eq!(potentially_valid.len(), 2);
    assert!(potentially_valid.contains_key(&priv_keys[0].0));
    assert!(potentially_valid.contains_key(&priv_keys[1].0));
    assert!(faulty.is_empty());
    {
      let generalized_bulletproofs::BatchVerifier { g, h, g_bold, h_bold, h_sum, additional } =
        &verifier;
      assert!(bool::from(!g.is_zero()));
      assert!(bool::from(!h.is_zero()));
      assert!(!g_bold.is_empty());
      assert!(!h_bold.is_empty());
      assert!(!h_sum.is_empty());
      assert!(!additional.is_empty());
    }

    Dkg::<Ed25519>::verify_structurally_valid_proofs(
      &mut OsRng,
      &generators,
      context,
      threshold,
      pub_keys.len().try_into().unwrap(),
      &pub_keys,
      &participations,
      &mut potentially_valid,
      &mut faulty,
      verifier,
    );
    assert_eq!(potentially_valid.len(), 1);
    assert!(potentially_valid.contains_key(&priv_keys[1].0));
    assert_eq!(faulty, HashSet::from([priv_keys[0].0]));
  }

  #[test]
  fn participating_weight() {
    use rand_core::OsRng;

    let mut pub_keys = vec![];
    for _ in 0 .. 5 {
      pub_keys.push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::G::random(&mut OsRng));
    }

    assert_eq!(Dkg::<Ed25519>::participating_weight(core::iter::empty(), &pub_keys[.. 0]), 0);
    assert_eq!(Dkg::<Ed25519>::participating_weight(core::iter::empty(), &pub_keys), 0);

    assert_eq!(
      Dkg::<Ed25519>::participating_weight([Participant::new(1).unwrap()].into_iter(), &pub_keys),
      1
    );
    assert_eq!(
      Dkg::<Ed25519>::participating_weight(
        [Participant::new(1).unwrap(), Participant::new(4).unwrap()].into_iter(),
        &pub_keys
      ),
      2
    );

    // The first `pub_key` (zero-indexed) corresponds to the first `Participant` (one-indexes)
    pub_keys[0] = pub_keys[3];
    // Specifying a single index should count for both participations
    assert_eq!(
      Dkg::<Ed25519>::participating_weight([Participant::new(1).unwrap()].into_iter(), &pub_keys),
      2
    );
    // Explicitly specifying both instances should not increase the weight
    assert_eq!(
      Dkg::<Ed25519>::participating_weight(
        [Participant::new(1).unwrap(), Participant::new(4).unwrap()].into_iter(),
        &pub_keys
      ),
      2
    );

    assert_eq!(Dkg::<Ed25519>::participating_weight(Participant::iter().take(5), &pub_keys), 5);
  }

  #[test]
  fn dkg() {
    use rand_core::OsRng;
    use rand::seq::SliceRandom as _;

    let max_threshold = 3;
    let max_participants = 4;
    let generators = Generators::<Ed25519>::new(max_threshold, max_participants);

    for participants in 1 ..= max_participants {
      for threshold in 1 ..= max_threshold.min(participants) {
        let mut context = [0; 32];
        OsRng.fill_bytes(&mut context);

        let mut priv_keys = vec![];
        let mut pub_keys = vec![];
        for i in 0 .. participants {
          let priv_key = Zeroizing::new(
            <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng),
          );
          pub_keys
            .push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key);
          priv_keys.push((Participant::new(1 + i).unwrap(), priv_key));
        }
        // Shuffle the private keys so we iterate over a random subset of them
        priv_keys.shuffle(&mut OsRng);

        let mut participations = HashMap::new();
        for (i, priv_key) in priv_keys.iter().take(usize::from(threshold)) {
          let participation = Dkg::<Ed25519>::participate(
            &mut OsRng,
            &generators,
            context,
            threshold,
            &pub_keys,
            priv_key,
          )
          .unwrap();

          // Test `read`, `write`
          {
            let mut serialized = vec![];
            participation.write(&mut serialized).unwrap();
            let mut serialized = serialized.as_slice();
            assert!(
              Participation::read(&mut serialized, threshold, participants).unwrap() ==
                participation
            );
            assert!(serialized.is_empty());
          }

          assert!(participations.insert(*i, participation).is_none());
        }

        let VerifyResult::Valid(dkg) = Dkg::<Ed25519>::verify(
          &mut OsRng,
          &generators,
          context,
          threshold,
          &pub_keys,
          &participations,
        )
        .unwrap() else {
          panic!("verify didn't return VerifyResult::Valid")
        };

        let mut group_key = None;
        let mut verification_shares = None;
        let mut keys = vec![];
        for (i, priv_key) in priv_keys {
          let these_keys = dkg.keys(&priv_key).into_iter().next().unwrap();

          assert_eq!(these_keys.params().i(), i);
          assert_eq!(these_keys.params().t(), threshold);
          assert_eq!(these_keys.params().n(), participants);

          group_key = group_key.or(Some(these_keys.group_key()));
          assert_eq!(Some(these_keys.group_key()), group_key);

          {
            let these_verification_shares = Participant::iter()
              .take(usize::from(participants))
              .map(|i| (i, these_keys.original_verification_share(i)))
              .collect::<HashMap<_, _>>();
            verification_shares = verification_shares.or(Some(these_verification_shares.clone()));
            assert_eq!(Some(these_verification_shares), verification_shares);
          }

          // Confirm our verification share corresponds to our secret share
          assert_eq!(
            <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::generator() *
              **these_keys.original_secret_share(),
            these_keys.original_verification_share(these_keys.params().i())
          );
          keys.push(these_keys);
        }

        let _ = dkg_recovery::recover_singular_key(&keys).unwrap();
      }
    }
  }
}
