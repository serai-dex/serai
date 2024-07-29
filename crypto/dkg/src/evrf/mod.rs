/*
  We implement a DKG using an eVRF, as detailed in the eVRF paper. For the eVRF itself, we do not
  use a Paillier-based construction, nor the detailed construction premised on a Bulletproof.

  For reference, the detailed construction premised on a Bulletproof involves two curves, notated
  here as `C` and `E`, where the scalar field of `C` is the field of `E`. Accordingly, Bulletproofs
  over `C` can efficiently perform group operations of points of curve `E`. Each participant has a
  private point (`P_i`) on curve `E` committed to over curve `C`. The eVRF selects a pair of
  scalars `a, b`, where the participant proves in-Bulletproof the points `A_i, B_i` are
  `a * P_i, b * P_i`. The eVRF proceeds to commit to `A_i.x + B_i.x` in a Pedersen Commitment.

  Our eVRF uses
  [Generalized Bulletproofs](
    https://repo.getmonero.org/monero-project/ccs-proposals
      /uploads/a9baa50c38c6312efc0fea5c6a188bb9/gbp.pdf
  ).
  This allows us much larger witnesses without growing the reference string, and enables us to
  efficiently sample challenges off in-circuit variables (via placing the variables in a vector
  commitment, then challenging from a transcript of the commitments). We proceed to use
  [elliptic curve divisors](
    https://repo.getmonero.org/-/project/54/
      uploads/eb1bf5b4d4855a3480c38abf895bd8e8/Veridise_Divisor_Proofs.pdf
  )
  (which require the ability to sample a challenge off in-circuit variables) to prove discrete
  logarithms efficiently.

  This is done via having a private scalar (`p_i`) on curve `E`, not a private point, and
  publishing the public key for it (`P_i = p_i * G`, where `G` is a generator of `E`). The eVRF
  samples two points with unknown discrete logarithms `A, B`, and the circuit proves a Pedersen
  Commitment commits to `(p_i * A).x + (p_i * B).x`.

  With the eVRF established, we now detail our other novel aspect. The eVRF paper expects secret
  shares to be sent to the other parties yet does not detail a precise way to do so. If we
  encrypted the secret shares with some stream cipher, each recipient would have to attest validity
  or accuse the sender of impropriety. We want an encryption scheme where anyone can verify the
  secret shares were encrypted properly, without additional info, efficiently.

  Please note from the published commitments, it's possible to calculcate a commitment to the
  secret share each party should receive (`V_i`).

  We have the sender sample two scalars per recipient, denoted `x_i, y_i` (where `i` is the
  recipient index). They perform the eVRF to prove a Pedersen Commitment commits to
  `z_i = (x_i * P_i).x + (y_i * P_i).x` and `x_i, y_i` are the discrete logarithms of `X_i, Y_i`
  over `G`. They then publish the encrypted share `s_i + z_i` and `X_i, Y_i`.

  The recipient is able to decrypt the share via calculating
  `s_i - ((p_i * X_i).x + (p_i * Y_i).x)`.

  To verify the secret share, we have the `F` terms of the Pedersen Commitments revealed (where
  `F, H` are generators of `C`, `F` is used for binding and `H` for blinding). This already needs
  to be done for the eVRF outputs used within the DKG, in order to obtain thecommitments to the
  coefficients. When we have the commitment `Z_i = ((p_i * A).x + (p_i * B).x) * F`, we simply
  check `s_i * F = Z_i + V_i`.

  In order to open the Pedersen Commitments to their `F` terms, we transcript the commitments and
  the claimed openings, then assign random weights to each pair of `(commitment, opening). The
  prover proves knowledge of the discrete logarithm of the sum weighted commitments, minus the sum
  sum weighted openings, over `H`.

  The benefit to this construction is that given an broadcast channel which is reliable and
  ordered, only `t` messages must be broadcast from honest parties in order to create a `t`-of-`n`
  multisig. If the encrypted secret shares were not verifiable, one would need at least `t + n`
  messages to ensure every participant has a correct dealing and can participate in future
  reconstructions of the secret. This would also require all `n` parties be online, whereas this is
  robust to threshold `t`.
*/

use core::ops::Deref;
use std::{
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
  Ciphersuite,
};
use multiexp::multiexp_vartime;

use generalized_bulletproofs::arithmetic_circuit_proof::*;
use ec_divisors::DivisorCurve;

use crate::{Participant, ThresholdParams, ThresholdCore, ThresholdKeys};

pub(crate) mod proof;
use proof::*;
pub use proof::{EvrfCurve, EvrfGenerators};

/// Participation in the DKG.
///
/// `Participation` is meant to be broadcast to all other participants over an authenticated,
/// reliable broadcast channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Participation<C: Ciphersuite> {
  proof: Vec<u8>,
  encrypted_secret_shares: HashMap<Participant, C::F>,
}

impl<C: Ciphersuite> Participation<C> {
  pub fn read<R: Read>(reader: &mut R, n: u16) -> io::Result<Self> {
    // TODO: Replace `len` with some calculcation deterministic to the params
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("<32-bit platform?");

    // Don't allocate a buffer for the claimed length
    // Read chunks until we reach the claimed length
    // This means if we were told to read GB, we must actually be sent GB before allocating as such
    const CHUNK_SIZE: usize = 1024;
    let mut proof = Vec::with_capacity(len.min(CHUNK_SIZE));
    while proof.len() < len {
      let next_chunk = (len - proof.len()).min(CHUNK_SIZE);
      let old_proof_len = proof.len();
      proof.resize(old_proof_len + next_chunk, 0);
      reader.read_exact(&mut proof[old_proof_len ..])?;
    }

    let mut encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
    for i in (1 ..= n).map(Participant) {
      encrypted_secret_shares.insert(i, C::read_F(reader)?);
    }

    Ok(Self { proof, encrypted_secret_shares })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.proof.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.proof)?;
    for i in (1 ..= u16::try_from(self.encrypted_secret_shares.len())
      .expect("writing a Participation which has a n > u16::MAX"))
      .map(Participant)
    {
      writer.write_all(self.encrypted_secret_shares[&i].to_repr().as_ref())?;
    }
    Ok(())
  }
}

fn polynomial<F: PrimeField + Zeroize>(
  coefficients: &[Zeroizing<F>],
  l: Participant,
) -> Zeroizing<F> {
  let l = F::from(u64::from(u16::from(l)));
  // This should never be reached since Participant is explicitly non-zero
  assert!(l != F::ZERO, "zero participant passed to polynomial");
  let mut share = Zeroizing::new(F::ZERO);
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    *share += coefficient.deref();
    if idx != (coefficients.len() - 1) {
      *share *= l;
    }
  }
  share
}

fn share_verification_statements<C: Ciphersuite>(
  rng: &mut (impl RngCore + CryptoRng),
  commitments: &[C::G],
  n: u16,
  encryption_commitments: &[C::G],
  encrypted_secret_shares: &HashMap<Participant, C::F>,
) -> (C::F, Vec<(C::F, C::G)>) {
  debug_assert_eq!(usize::from(n), encryption_commitments.len());
  debug_assert_eq!(usize::from(n), encrypted_secret_shares.len());

  let mut g_scalar = C::F::ZERO;
  let mut pairs = Vec::with_capacity(commitments.len() + encryption_commitments.len());
  for commitment in commitments {
    pairs.push((C::F::ZERO, *commitment));
  }

  let mut weight;
  for (i, enc_share) in encrypted_secret_shares {
    let enc_commitment = encryption_commitments[usize::from(u16::from(*i)) - 1];

    weight = C::F::random(&mut *rng);

    // s_i F
    g_scalar += weight * enc_share;
    // - Z_i
    let weight = -weight;
    pairs.push((weight, enc_commitment));
    // - V_i
    {
      let i = C::F::from(u64::from(u16::from(*i)));
      // The first `commitments.len()` pairs are for the commitments
      (0 .. commitments.len()).fold(weight, |exp, j| {
        pairs[j].0 += exp;
        exp * i
      });
    }
  }

  (g_scalar, pairs)
}

/// Errors from the eVRF DKG.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum EvrfError {
  #[error("n, the amount of participants, exceeded a u16")]
  TooManyParticipants,
  #[error("the threshold t wasn't in range 1 <= t <= n")]
  InvalidThreshold,
  #[error("a public key was the identity point")]
  PublicKeyWasIdentity,
  #[error("participating in a DKG we aren't a participant in")]
  NotAParticipant,
  #[error("a participant with an unrecognized ID participated")]
  NonExistentParticipant,
  #[error("the passed in generators did not have enough generators for this DKG")]
  NotEnoughGenerators,
}

/// The result of calling EvrfDkg::verify.
pub enum VerifyResult<C: EvrfCurve> {
  Valid(EvrfDkg<C>),
  Invalid(Vec<Participant>),
  NotEnoughParticipants,
}

/// Struct to perform/verify the DKG with.
#[derive(Debug)]
pub struct EvrfDkg<C: EvrfCurve> {
  t: u16,
  n: u16,
  evrf_public_keys: Vec<<C::EmbeddedCurve as Ciphersuite>::G>,
  group_key: C::G,
  verification_shares: HashMap<Participant, C::G>,
  encrypted_secret_shares:
    HashMap<Participant, HashMap<Participant, ([<C::EmbeddedCurve as Ciphersuite>::G; 2], C::F)>>,
}

impl<C: EvrfCurve> EvrfDkg<C>
where
  <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
    DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
{
  // Form the initial transcript for the proofs.
  fn initial_transcript(
    invocation: [u8; 32],
    evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
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
  ///
  /// Public keys are not allowed to be the identity point. This will error if any are.
  pub fn participate(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &EvrfGenerators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Result<Vec<Participation<C>>, EvrfError> {
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else { Err(EvrfError::TooManyParticipants)? };
    if (t == 0) || (t > n) {
      Err(EvrfError::InvalidThreshold)?;
    }
    if evrf_public_keys.iter().any(|key| bool::from(key.is_identity())) {
      Err(EvrfError::PublicKeyWasIdentity)?;
    };

    let evrf_public_key = <C::EmbeddedCurve as Ciphersuite>::generator() * evrf_private_key.deref();
    let mut res = vec![];
    for (i, this_evrf_public_key) in evrf_public_keys.iter().enumerate() {
      let i = u16::try_from(i + 1).expect("n <= u16::MAX yet not i?");

      if *this_evrf_public_key != evrf_public_key {
        continue;
      }

      let transcript = Self::initial_transcript(context, evrf_public_keys, t);
      // Further bind to the participant index so each index gets unique generators
      // This allows reusing eVRF public keys as the prover
      let mut per_proof_transcript = Blake2s256::new();
      per_proof_transcript.update(transcript);
      per_proof_transcript.update(i.to_le_bytes());

      // The above transcript is expected to be binding to all arguments here
      // The generators are constant to this ciphersuite's generator, and the parameters are
      // transcripted
      let EvrfProveResult { coefficients, encryption_masks, proof } = match Evrf::prove(
        rng,
        &generators.0,
        per_proof_transcript.finalize().into(),
        usize::from(t),
        evrf_public_keys,
        evrf_private_key,
      ) {
        Ok(res) => res,
        Err(AcError::NotEnoughGenerators) => Err(EvrfError::NotEnoughGenerators)?,
        Err(
          AcError::DifferingLrLengths |
          AcError::InconsistentAmountOfConstraints |
          AcError::ConstrainedNonExistentTerm |
          AcError::ConstrainedNonExistentCommitment |
          AcError::InconsistentWitness |
          AcError::Ip(_) |
          AcError::IncompleteProof,
        ) => {
          panic!("failed to prove for the eVRF proof")
        }
      };

      let mut encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
      for (l, encryption_mask) in (1 ..= n).map(Participant).zip(encryption_masks) {
        let share = polynomial::<C::F>(&coefficients, l);
        encrypted_secret_shares.insert(l, *share + *encryption_mask);
      }

      res.push(Participation { proof, encrypted_secret_shares });
    }

    if res.is_empty() {
      Err(EvrfError::NotAParticipant)?;
    }

    Ok(res)
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
    generators: &EvrfGenerators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
    participations: &HashMap<Participant, Participation<C>>,
  ) -> Result<VerifyResult<C>, EvrfError> {
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else { Err(EvrfError::TooManyParticipants)? };
    if (t == 0) || (t > n) {
      Err(EvrfError::InvalidThreshold)?;
    }
    if evrf_public_keys.iter().any(|key| bool::from(key.is_identity())) {
      Err(EvrfError::PublicKeyWasIdentity)?;
    };
    for i in participations.keys() {
      if u16::from(*i) > n {
        Err(EvrfError::NonExistentParticipant)?;
      }
    }

    let mut valid = HashMap::with_capacity(participations.len());
    let mut faulty = HashSet::new();

    let transcript = Self::initial_transcript(context, evrf_public_keys, t);

    let mut evrf_verifier = generators.0.batch_verifier();
    for (i, participation) in participations {
      let mut per_proof_transcript = Blake2s256::new();
      per_proof_transcript.update(transcript);
      per_proof_transcript.update(u16::from(*i).to_le_bytes());

      // Clone the verifier so if this proof is faulty, it doesn't corrupt the verifier
      let mut verifier_clone = evrf_verifier.clone();
      let Ok(data) = Evrf::<C>::verify(
        rng,
        &generators.0,
        &mut verifier_clone,
        per_proof_transcript.finalize().into(),
        usize::from(t),
        evrf_public_keys,
        evrf_public_keys[usize::from(u16::from(*i)) - 1],
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
        let mut evrf_verifier = generators.0.batch_verifier();
        Evrf::<C>::verify(
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
        let mut g_scalar = C::F::ZERO;
        let mut pairs = Vec::with_capacity(valid.len() * (usize::from(t) + evrf_public_keys.len()));
        for (i, (encrypted_secret_shares, data)) in &valid {
          let (this_g_scalar, mut these_pairs) = share_verification_statements::<C>(
            &mut *rng,
            &data.coefficients,
            evrf_public_keys
              .len()
              .try_into()
              .expect("n prior checked to be <= u16::MAX couldn't be converted to a u16"),
            &data.encryption_commitments,
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
              This is only possible because already interpolated the commitments to verify the
              encrypted secret share.
            */
            let sum_encrypted_secret_share =
              sum_encrypted_secret_shares.get(j).copied().unwrap_or(C::F::ZERO);
            let sum_mask = sum_masks.get(j).copied().unwrap_or(C::G::identity());
            sum_encrypted_secret_shares.insert(*j, sum_encrypted_secret_share + enc_share);

            let j_index = usize::from(u16::from(*j)) - 1;
            sum_masks.insert(*j, sum_mask + data.encryption_commitments[j_index]);

            formatted_encrypted_secret_shares.insert(*j, (data.ecdh_keys[j_index], *enc_share));
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

    if valid.len() < usize::from(t) {
      return Ok(VerifyResult::NotEnoughParticipants);
    }

    // If we now have >= t participations, calculate the group key and verification shares

    // The group key is the sum of the zero coefficients
    let group_key = valid.values().map(|(_, evrf_data)| evrf_data.coefficients[0]).sum::<C::G>();

    // Calculate each user's verification share
    let mut verification_shares = HashMap::with_capacity(usize::from(n));
    for i in (1 ..= n).map(Participant) {
      verification_shares
        .insert(i, (C::generator() * sum_encrypted_secret_shares[&i]) - sum_masks[&i]);
    }

    Ok(VerifyResult::Valid(EvrfDkg {
      t,
      n,
      evrf_public_keys: evrf_public_keys.to_vec(),
      group_key,
      verification_shares,
      encrypted_secret_shares: all_encrypted_secret_shares,
    }))
  }

  pub fn keys(
    &self,
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Vec<ThresholdKeys<C>> {
    let evrf_public_key = <C::EmbeddedCurve as Ciphersuite>::generator() * evrf_private_key.deref();
    let mut is = Vec::with_capacity(1);
    for (i, evrf_key) in self.evrf_public_keys.iter().enumerate() {
      if *evrf_key == evrf_public_key {
        let i = u16::try_from(i).expect("n <= u16::MAX yet i > u16::MAX?");
        let i = Participant(1 + i);
        is.push(i);
      }
    }

    let mut res = Vec::with_capacity(is.len());
    for i in is {
      let mut secret_share = Zeroizing::new(C::F::ZERO);
      for shares in self.encrypted_secret_shares.values() {
        let (ecdh_keys, enc_share) = shares[&i];

        let mut ecdh = Zeroizing::new(C::F::ZERO);
        for point in ecdh_keys {
          let (mut x, mut y) =
            <C::EmbeddedCurve as Ciphersuite>::G::to_xy(point * evrf_private_key.deref()).unwrap();
          *ecdh += x;
          x.zeroize();
          y.zeroize();
        }
        *secret_share += enc_share - ecdh.deref();
      }

      debug_assert_eq!(self.verification_shares[&i], C::generator() * secret_share.deref());

      res.push(ThresholdKeys::from(ThresholdCore {
        params: ThresholdParams::new(self.t, self.n, i).unwrap(),
        secret_share,
        group_key: self.group_key,
        verification_shares: self.verification_shares.clone(),
      }));
    }
    res
  }
}
