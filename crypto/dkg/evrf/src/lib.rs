#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref;
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
  collections::{HashSet, HashMap},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use blake2::{Digest, Blake2s256};
use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
  },
  WrappedGroup, GroupIo,
};
use multiexp::multiexp_vartime;

use generalized_bulletproofs::arithmetic_circuit_proof::*;
use ec_divisors::DivisorCurve;

pub use dkg::*;

mod utils;
pub(crate) use utils::*;

mod curves;
pub use curves::*;

mod proof;
use proof::*;

#[cfg(test)]
mod tests;

/// Participation in the DKG.
///
/// `Participation` is meant to be broadcast to all other participants over an authenticated,
/// reliable broadcast channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Participation<C: Curves> {
  proof: Vec<u8>,
  encrypted_secret_shares: HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>,
}

impl<C: Curves> Participation<C> {
  pub fn read<R: Read>(reader: &mut R, n: u16) -> io::Result<Self> {
    // Ban <32-bit platforms, allowing us to assume `u32` -> `usize` works
    const _NO_16_BIT_PLATFORMS: [(); (usize::BITS - u32::BITS) as usize] = [(); _];

    // TODO: Replace `len` with some calculation deterministic to the params
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("<32-bit platform?");

    /*
      Don't allocate a buffer for the claimed length.

      We read chunks of a fixed-length until we reach the claimed length, preventing an adversary
      from forcing us to allocate GB unless the proof is actually GB long.
    */
    const CHUNK_SIZE: usize = 1024;
    let mut proof = Vec::with_capacity(len.min(CHUNK_SIZE));
    while proof.len() < len {
      let next_chunk = (len - proof.len()).min(CHUNK_SIZE);
      let old_proof_len = proof.len();
      proof.resize(old_proof_len + next_chunk, 0);
      reader.read_exact(&mut proof[old_proof_len ..])?;
    }

    let mut encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
    for i in Participant::iter().take(usize::from(n)) {
      encrypted_secret_shares.insert(i, <C::ToweringCurve as GroupIo>::read_F(reader)?);
    }

    Ok(Self { proof, encrypted_secret_shares })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.proof.len()).unwrap().to_le_bytes())?;
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

/// The result of calling `Dkg::verify`.
pub enum VerifyResult<C: Curves> {
  /// The DKG participations were valid.
  Valid(Dkg<C>),
  /// The DKG participants were invalid, identifying the faulty participants.
  Invalid(Vec<Participant>),
  /// Not enough participations were provided, yet no provided participations were faulty.
  NotEnoughParticipants,
}

/// Struct representing a DKG.
#[derive(Debug)]
pub struct Dkg<C: Curves> {
  t: u16,
  n: u16,
  evrf_public_keys: Vec<<C::EmbeddedCurve as WrappedGroup>::G>,
  verification_shares: HashMap<Participant, <C::ToweringCurve as WrappedGroup>::G>,
  #[allow(clippy::type_complexity)]
  encrypted_secret_shares: HashMap<
    Participant,
    HashMap<
      Participant,
      ([<C::EmbeddedCurve as WrappedGroup>::G; 2], <C::ToweringCurve as WrappedGroup>::F),
    >,
  >,
}

impl<C: Curves> Dkg<C> {
  // Form the initial transcript for the proofs.
  fn initial_transcript(
    invocation: [u8; 32],
    evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
    t: u16,
  ) -> [u8; 32] {
    let mut transcript = Blake2s256::new();
    transcript.update(invocation);
    for key in evrf_public_keys {
      transcript.update(key.to_bytes().as_ref());
    }
    transcript.update(t.to_le_bytes());
    transcript.finalize().into()
  }

  /// Participate in performing the DKG for the specified parameters.
  ///
  /// The context MUST be unique across invocations. Reuse of context will lead to sharing
  /// prior-shared secrets.
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
    };
    // This also ensures the private key is not 0, due to the prior check the identity point wasn't
    // present
    let evrf_public_key =
      <C::EmbeddedCurve as WrappedGroup>::generator() * evrf_private_key.deref();
    if !evrf_public_keys.contains(&evrf_public_key) {
      Err(Error::NotAParticipant)?;
    };

    let transcript = Self::initial_transcript(context, evrf_public_keys, t);
    // Bind to the participant
    let mut per_proof_transcript = Blake2s256::new();
    per_proof_transcript.update(transcript);
    per_proof_transcript.update(evrf_public_key.to_bytes());

    let ProveResult { coefficients, encryption_keys, proof } = match Proof::<C>::prove(
      rng,
      &generators.0,
      per_proof_transcript.finalize().into(),
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
      encrypted_secret_shares.insert(l, *share + *encryption_key);
    }

    Ok(Participation { proof, encrypted_secret_shares })
  }
}

/// Batch-verifiable statements to verify encrypted secret shares.
#[allow(clippy::type_complexity)]
fn verifiable_encryption_statements<C: Curves>(
  rng: &mut (impl RngCore + CryptoRng),
  coefficients: &[<C::ToweringCurve as WrappedGroup>::G],
  encryption_key_commitments: &[<C::ToweringCurve as WrappedGroup>::G],
  encrypted_secret_shares: &HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>,
) -> (
  <C::ToweringCurve as WrappedGroup>::F,
  Vec<(<C::ToweringCurve as WrappedGroup>::F, <C::ToweringCurve as WrappedGroup>::G)>,
) {
  let mut g_scalar = <C::ToweringCurve as WrappedGroup>::F::ZERO;
  let mut pairs = Vec::with_capacity(coefficients.len() + encryption_key_commitments.len());

  // Push on the commitments to the polynomial being secret-shared
  for coefficient in coefficients {
    // This uses `0` as we'll add to it later, given its fixed position
    pairs.push((<C::ToweringCurve as WrappedGroup>::F::ZERO, *coefficient));
  }

  for (i, encrypted_secret_share) in encrypted_secret_shares {
    let encryption_key_commitment = encryption_key_commitments[usize::from(u16::from(*i)) - 1];

    let weight = <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng);

    /*
      The encrypted secret share scaling `G`, minus the encryption key commitment, minus the
      ommitment to the secret share, should equal the identity point.

      We actually subtract the encrypted share to optimize the amount of negations we perform.
    */
    g_scalar -= weight * encrypted_secret_share;
    pairs.push((weight, encryption_key_commitment));
    // Calculate the commitment to the secret share via the commitments to the polynomial
    {
      let i = <C::ToweringCurve as WrappedGroup>::F::from(u64::from(u16::from(*i)));
      (0 .. coefficients.len()).fold(weight, |exp, j| {
        pairs[j].0 += exp;
        exp * i
      });
    }
  }

  (g_scalar, pairs)
}

impl<C: Curves> Dkg<C> {
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
    };
    for i in participations.keys() {
      if u16::from(*i) > n {
        Err(Error::NonExistentParticipant)?;
      }
    }

    let mut valid = HashMap::with_capacity(participations.len());
    let mut faulty = HashSet::new();

    let transcript = Self::initial_transcript(context, evrf_public_keys, t);

    let mut evrf_verifier = generalized_bulletproofs::Generators::batch_verifier();
    for (i, participation) in participations {
      let evrf_public_key = evrf_public_keys[usize::from(u16::from(*i)) - 1];

      let mut per_proof_transcript = Blake2s256::new();
      per_proof_transcript.update(transcript);
      per_proof_transcript.update(evrf_public_key.to_bytes());

      // Clone the verifier so if this proof is faulty, it doesn't corrupt the verifier
      let mut verifier_clone = evrf_verifier.clone();
      let Ok(data) = Proof::<C>::verify(
        rng,
        &generators.0,
        &mut verifier_clone,
        per_proof_transcript.finalize().into(),
        usize::from(t),
        evrf_public_keys,
        evrf_public_key,
        &participation.proof,
      ) else {
        faulty.insert(*i);
        continue;
      };
      evrf_verifier = verifier_clone;

      valid.insert(*i, (participation.encrypted_secret_shares.clone(), data));
    }
    debug_assert_eq!(valid.len() + faulty.len(), participations.len());

    // Perform the batch verification of the eVRFs
    if !generators.0.verify(evrf_verifier) {
      // If the batch failed, verify them each individually
      for (i, participation) in participations {
        if faulty.contains(i) {
          continue;
        }
        let mut evrf_verifier = generalized_bulletproofs::Generators::batch_verifier();
        Proof::<C>::verify(
          rng,
          &generators.0,
          &mut evrf_verifier,
          context,
          usize::from(t),
          evrf_public_keys,
          evrf_public_keys[usize::from(u16::from(*i)) - 1],
          &participation.proof,
        )
        .expect("evrf failed basic checks yet prover wasn't prior marked faulty");
        if !generators.0.verify(evrf_verifier) {
          valid.remove(i);
          faulty.insert(*i);
        }
      }
    }
    debug_assert_eq!(valid.len() + faulty.len(), participations.len());

    // Perform the batch verification of the shares
    let mut sum_encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
    let mut sum_masks = HashMap::with_capacity(usize::from(n));
    let mut all_encrypted_secret_shares = HashMap::with_capacity(usize::from(t));
    {
      let mut share_verification_statements_actual = HashMap::with_capacity(valid.len());
      if !{
        let mut g_scalar = <C::ToweringCurve as WrappedGroup>::F::ZERO;
        let mut pairs = Vec::with_capacity(valid.len() * (usize::from(t) + evrf_public_keys.len()));
        for (i, (encrypted_secret_shares, data)) in &valid {
          let (this_g_scalar, mut these_pairs) = verifiable_encryption_statements::<C>(
            &mut *rng,
            &data.coefficients,
            &data.encryption_key_commitments,
            encrypted_secret_shares,
          );
          // Queue this into our batch
          g_scalar += this_g_scalar;
          pairs.extend(&these_pairs);

          // Also push this g_scalar onto these_pairs so these_pairs can be verified individually
          // upon error
          these_pairs.push((this_g_scalar, generators.0.g()));
          share_verification_statements_actual.insert(*i, these_pairs);

          // Also format this data as we'd need it upon success
          let mut formatted_encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
          for (j, enc_share) in encrypted_secret_shares {
            /*
              We calculcate verification shares as the sum of the encrypted scalars, minus their
              masks. This only does one scalar multiplication, and `1+t` point additions (with
              one negation), and is accordingly much cheaper than interpolating the commitments.
              This is only possible because we already interpolated the commitments to verify the
              encrypted secret share.
            */
            let sum_encrypted_secret_share = sum_encrypted_secret_shares
              .get(j)
              .copied()
              .unwrap_or(<C::ToweringCurve as WrappedGroup>::F::ZERO);
            let sum_mask = sum_masks
              .get(j)
              .copied()
              .unwrap_or(<C::ToweringCurve as WrappedGroup>::G::identity());
            sum_encrypted_secret_shares.insert(*j, sum_encrypted_secret_share + enc_share);

            let j_index = usize::from(u16::from(*j)) - 1;
            sum_masks.insert(*j, sum_mask + data.encryption_key_commitments[j_index]);

            formatted_encrypted_secret_shares
              .insert(*j, (data.ecdh_commitments[j_index], *enc_share));
          }
          all_encrypted_secret_shares.insert(*i, formatted_encrypted_secret_shares);
        }
        pairs.push((g_scalar, generators.0.g()));
        bool::from(multiexp_vartime(&pairs).is_identity())
      } {
        // If the batch failed, verify them each individually
        for (i, pairs) in share_verification_statements_actual {
          if !bool::from(multiexp_vartime(&pairs).is_identity()) {
            valid.remove(&i);
            faulty.insert(i);
          }
        }
      }
    }
    debug_assert_eq!(valid.len() + faulty.len(), participations.len());

    let mut faulty = faulty.into_iter().collect::<Vec<_>>();
    if !faulty.is_empty() {
      faulty.sort_unstable();
      return Ok(VerifyResult::Invalid(faulty));
    }

    // We check at least t key shares of people have participated in contributing entropy
    // Since the key shares of the participants exceed t, meaning if they're malicious they can
    // reconstruct the key regardless, this is safe to the threshold
    {
      let mut participating_weight = 0;
      let mut evrf_public_keys_mut = evrf_public_keys.to_vec();
      for i in valid.keys() {
        let evrf_public_key = evrf_public_keys[usize::from(u16::from(*i)) - 1];

        // Remove this key from the Vec to prevent double-counting
        /*
          Double-counting would be a risk if multiple participants shared an eVRF public key and
          participated. This code does still allow such participants (in order to let participants
          be weighted), and any one of them participating will count as all participating. This is
          fine as any one such participant will be able to decrypt the shares for themselves and
          all other participants, so this is still a key generated by an amount of participants who
          could simply reconstruct the key.
        */
        let start_len = evrf_public_keys_mut.len();
        evrf_public_keys_mut.retain(|key| *key != evrf_public_key);
        let end_len = evrf_public_keys_mut.len();
        let count = start_len - end_len;

        participating_weight += count;
      }
      if participating_weight < usize::from(t) {
        return Ok(VerifyResult::NotEnoughParticipants);
      }
    }

    // If we now have >= t participations, output the result

    // Calculate each user's verification share
    let mut verification_shares = HashMap::with_capacity(usize::from(n));
    for i in Participant::iter().take(usize::from(n)) {
      verification_shares.insert(
        i,
        (<C::ToweringCurve as WrappedGroup>::generator() * sum_encrypted_secret_shares[&i]) -
          sum_masks[&i],
      );
    }

    Ok(VerifyResult::Valid(Dkg {
      t,
      n,
      evrf_public_keys: evrf_public_keys.to_vec(),
      verification_shares,
      encrypted_secret_shares: all_encrypted_secret_shares,
    }))
  }

  /// Retrieve keys from a successful DKG.
  ///
  /// This will return _all_ keys belong to the participant.
  pub fn keys(
    &self,
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as WrappedGroup>::F>,
  ) -> Vec<ThresholdKeys<C::ToweringCurve>> {
    let evrf_public_key =
      <C::EmbeddedCurve as WrappedGroup>::generator() * evrf_private_key.deref();
    let mut is = Vec::with_capacity(1);
    for (i, evrf_key) in Participant::iter().zip(self.evrf_public_keys.iter()) {
      if *evrf_key == evrf_public_key {
        is.push(i);
      }
    }

    let mut res = Vec::with_capacity(is.len());
    for i in is {
      let mut secret_share = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
      for shares in self.encrypted_secret_shares.values() {
        let (ecdh_commitments, encrypted_secret_share) = shares[&i];

        let mut ecdh = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
        for point in ecdh_commitments {
          let (mut x, mut y) =
            <C::EmbeddedCurve as WrappedGroup>::G::to_xy(point * evrf_private_key.deref()).unwrap();
          *ecdh += x;
          x.zeroize();
          y.zeroize();
        }
        *secret_share += encrypted_secret_share - ecdh.deref();
      }
      debug_assert_eq!(
        self.verification_shares[&i],
        <C::ToweringCurve as WrappedGroup>::generator() * secret_share.deref()
      );

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
