use core::ops::Deref;
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite,
};
use multiexp::multiexp_vartime;

use generalized_bulletproofs::{Generators, BatchVerifier, arithmetic_circuit_proof::*};
use ec_divisors::DivisorCurve;
use evrf::*;

use crate::{
  Participant, DkgError, ThresholdParams, ThresholdCore,
  encryption::{ReadWrite, EncryptedMessage, Encryption, EncryptionKeyProof},
  pedpop::SecretShare,
};

type EvrfError<C> = DkgError<EncryptionKeyProof<C>>;

/// The commitments message, intended to be broadcast to all other parties.
///
/// Every participant should only provide one set of commitments to all parties. If any
/// participant sends multiple sets of commitments, they are faulty and should be presumed
/// malicious. As this library does not handle networking, it is unable to detect if any
/// participant is so faulty. That responsibility lies with the caller.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Commitments {
  proof: Vec<u8>,
}

impl ReadWrite for Commitments {
  fn read<R: Read>(reader: &mut R, _params: ThresholdParams) -> io::Result<Self> {
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

    Ok(Commitments { proof })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.proof.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.proof)?;
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

/// Struct to perform/verify the DKG with.
#[derive(Debug, Zeroize)]
pub struct EvrfDkg;

enum AccumulationStrategy<C: EvrfCurve> {
  #[rustfmt::skip]
  WaitingForThreshold {
    pending_verification: HashMap<Participant, (Commitments, Zeroizing<C::F>)>,
  },
  Incremental {
    accumulated: HashMap<Participant, (Vec<C::G>, Zeroizing<C::F>)>,
  },
}

struct EvrfAccumulatorCore<'a, C: EvrfCurve> {
  generators: &'a Generators<C>,
  evrf_public_keys: Vec<<C::EmbeddedCurve as Ciphersuite>::G>,
  context: [u8; 32],
  params: ThresholdParams,
}

pub struct EvrfAccumulator<'a, C: EvrfCurve> {
  core: EvrfAccumulatorCore<'a, C>,

  encryption: Encryption<C::EmbeddedCurve>,

  our_commitments: Vec<C::G>,
  accumulation: AccumulationStrategy<C>,
  resulting_share: Zeroizing<C::F>,
}

pub struct EvrfShare<C: EvrfCurve> {
  commitments: Commitments,
  shares: HashMap<Participant, EncryptedMessage<C::EmbeddedCurve, SecretShare<C::F>>>,
}

impl EvrfDkg {
  /// Participate in performing the DKG for the specified parameters.
  ///
  /// The context MUST be unique across invocations. Reuse of context will lead to sharing
  /// prior-shared secrets.
  // TODO: Have this return an accumulator
  pub fn share<'a, C: EvrfCurve>(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &'a Generators<C>,
    evrf_public_keys: Vec<<C::EmbeddedCurve as Ciphersuite>::G>,
    context: [u8; 32],
    params: ThresholdParams,
    evrf_private_key: Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Result<(EvrfAccumulator<'a, C>, EvrfShare<C>), AcError>
  where
    <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
      DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
  {
    // TODO: Confirm `n` == the amount of evrf_public_keys
    // TODO: Confirm evrf_public_keys[i] == evrf_private_key * G
    // TODO: Hash context to include the list of public keys

    let EvrfProveResult { scalars, proof } =
      Evrf::prove(rng, generators, evrf_private_key.clone(), context, usize::from(params.t()))?;

    /*
      We reuse the eVRF key for receiving encrypted messages.

      For encrypting to other parties, we use a randomly generated ephemeral key, so there's no
      risk there.

      When decrypting, we calculcate the ECDH of our private key with the ephemeral public key. If
      the decryption fails, we publish the ECDH with a proof. If the ephemeral public key is one
      of the eVRF points, this would leak a secret. Since ephemeral public keys must be associated
      with PoKs for their discrete logarithms, and the eVRF points have unknown discrete
      logarithms, this is still secure.
    */
    let mut encryption = Encryption::new(context, params.i(), evrf_private_key);
    for (i, evrf_public_key) in evrf_public_keys.iter().enumerate() {
      encryption
        .register(Participant::new(u16::try_from(i + 1).unwrap()).unwrap(), *evrf_public_key);
    }

    let mut resulting_share = None;
    let mut shares = HashMap::new();
    for l in (1 ..= params.n()).map(Participant) {
      let share = polynomial::<C::F>(&scalars, l);

      // Don't insert our own share as we don't need to send out our own share
      if l == params.i() {
        resulting_share = Some(share);
        continue;
      }

      let share_bytes = Zeroizing::new(SecretShare::<C::F>(share.to_repr()));
      shares.insert(l, encryption.encrypt(rng, l, share_bytes));
    }

    let accumulator = EvrfAccumulator {
      core: EvrfAccumulatorCore { generators, evrf_public_keys, context, params },

      encryption,

      our_commitments: scalars.iter().map(|scalar| C::generator() * **scalar).collect(),
      accumulation: AccumulationStrategy::WaitingForThreshold {
        pending_verification: HashMap::new(),
      },
      resulting_share: resulting_share.unwrap(),
    };
    Ok((accumulator, EvrfShare { commitments: Commitments { proof }, shares }))
  }
}

fn exponential<C: Ciphersuite>(i: Participant, values: &[C::G]) -> C::G {
  let i = C::F::from(u16::from(i).into());
  let mut res = Vec::with_capacity(values.len());
  (0 .. values.len()).fold(C::F::ONE, |exp, l| {
    res.push((exp, values[l]));
    exp * i
  });
  multiexp_vartime(&res)
}

struct Blame;

impl<'a, C: EvrfCurve> EvrfAccumulatorCore<'a, C>
where
  <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
    DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
{
  fn verify_evrf(
    &mut self,
    rng: &mut (impl RngCore + CryptoRng),
    verifier: &mut BatchVerifier<C>,
    from: Participant,
    commitments: &Commitments,
  ) -> Result<Vec<C::G>, ()> {
    // TODO: Verify from is in-range and distinct from params.i()
    let from_public_key = self.evrf_public_keys[usize::from(u16::from(from) - 1)];
    Evrf::verify(
      rng,
      self.generators,
      verifier,
      from_public_key,
      self.context,
      usize::from(self.params.t()),
      &commitments.proof,
    )
  }
}

impl<'a, C: EvrfCurve> EvrfAccumulator<'a, C>
where
  <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
    DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
{
  /// Verify a secret sharing.
  pub fn accumulate(
    &mut self,
    rng: &mut (impl RngCore + CryptoRng),
    from: Participant,
    commitments: Commitments,
    share: EncryptedMessage<C::EmbeddedCurve, SecretShare<C::F>>,
  ) -> Vec<Blame> {
    // TODO: Confirm `n` == the amount of evrf_public_keys
    // TODO: Confirm evrf_public_keys[i] == evrf_private_key * G
    // TODO: Hash context to include the list of public keys
    // TODO: Check not prior accumulated

    // This uses an ephemeral BatchVerifier as if we verify an invalid proof, it'll corrupt the
    // BatchVerifier. If we tried to form a BatchVerifier, it'd need reconstruction on such error,
    // increasing complexity and opening potential DoS vectors
    let mut ephemeral_verifier = self.core.generators.batch_verifier();
    let Ok(actual_commitments) =
      self.core.verify_evrf(rng, &mut ephemeral_verifier, from, &commitments)
    else {
      return vec![Blame];
    };

    // Decrypt the share
    let mut batch = multiexp::BatchVerifier::new(1);
    let (mut share_bytes, blame) = self.encryption.decrypt(rng, &mut batch, (), from, share);
    let Some(share) = Option::<C::F>::from(C::F::from_repr(share_bytes.0)) else {
      return vec![Blame];
    };
    let share = Zeroizing::new(share);
    share_bytes.zeroize();

    if exponential::<C>(self.core.params.i(), &actual_commitments) !=
      (self.core.generators.g() * *share)
    {
      return vec![Blame];
    }

    match &mut self.accumulation {
      AccumulationStrategy::WaitingForThreshold { ref mut pending_verification } => {
        pending_verification.insert(from, (commitments, share));

        // If we now have the necessary threshold to consider this DKG as having succeeded, verify
        // the proofs with a batch verification
        if pending_verification.len() == usize::from(self.core.params.t()) {
          let mut batch_verifier = self.core.generators.batch_verifier();
          let mut all_pending_verification = HashMap::new();
          for (participant, (commitments, share)) in &mut *pending_verification {
            let actual_commitments = self
              .core
              .verify_evrf(rng, &mut batch_verifier, *participant, commitments)
              .expect("prior verified evrf proof now errors upon verification");
            all_pending_verification.insert(*participant, (actual_commitments, share.clone()));
          }

          if self.core.generators.verify(batch_verifier) {
            // If the verification succeeded, marked the proofs pending verification as accumulated
            self.accumulation =
              AccumulationStrategy::Incremental { accumulated: all_pending_verification };
          } else {
            // Find the faulty proof(s)
            let mut accumulated = HashMap::new();
            let mut blames = vec![];
            for (participant, (commitments, share)) in &mut *pending_verification {
              let mut verifier = self.core.generators.batch_verifier();
              let actual_commitments = self
                .core
                .verify_evrf(rng, &mut verifier, *participant, commitments)
                .expect("prior verified evrf proof now errors upon verification");
              if self.core.generators.verify(verifier) {
                accumulated.insert(*participant, (actual_commitments, share.clone()));
              } else {
                blames.push(Blame);
              }
            }
            self.accumulation = AccumulationStrategy::Incremental { accumulated };

            // Now that we've marked all proofs as accumulated/faulty, return the blame
            return blames;
          }
        }
      }
      AccumulationStrategy::Incremental { ref mut accumulated } => {
        if self.core.generators.verify(ephemeral_verifier) {
          accumulated.insert(from, (actual_commitments, share));
        } else {
          return vec![Blame];
        }
      }
    }

    vec![]
  }

  #[allow(clippy::needless_pass_by_value)]
  pub fn process_blame(&mut self, blame: Blame) {
    todo!("TODO");
  }

  pub fn introspect_group_key(&self) -> Result<C::G, ()> {
    let AccumulationStrategy::Incremental { accumulated } = &self.accumulation else { Err(())? };
    if (1 + accumulated.len()) < usize::from(self.core.params.t()) {
      Err(())?
    }
    Ok(
      accumulated.values().map(|(commitments, _)| commitments[0]).sum::<C::G>() +
        self.our_commitments[0],
    )
  }

  /// Finish accumulation.
  pub fn complete(mut self) -> Result<ThresholdCore<C>, ()> {
    let AccumulationStrategy::Incremental { accumulated } = self.accumulation else { Err(())? };

    if (1 + accumulated.len()) < usize::from(self.core.params.t()) {
      Err(())?
    }

    let commitments = accumulated
      .values()
      .map(|(commitments, _)| commitments)
      .chain(core::iter::once(&self.our_commitments));
    // Stripe commitments per t and sum them in advance
    // Calculating verification shares relies on these sums so preprocessing them is a massive
    // speedup
    let mut stripes = Vec::with_capacity(usize::from(self.core.params.t()));
    for t in 0 .. usize::from(self.core.params.t()) {
      stripes.push(commitments.clone().map(|commitments| commitments[t]).sum());
    }

    // Calculate each user's verification share
    let mut verification_shares = HashMap::new();
    for i in (1 ..= self.core.params.n()).map(Participant) {
      verification_shares.insert(i, exponential::<C>(i, &stripes));
    }

    for (_, share) in accumulated.values() {
      *self.resulting_share += **share;
    }
    Ok(ThresholdCore {
      params: self.core.params,
      secret_share: self.resulting_share,
      group_key: stripes[0],
      verification_shares,
    })
  }
}
