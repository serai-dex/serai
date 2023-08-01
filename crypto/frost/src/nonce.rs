// FROST defines its nonce as sum(Di, Ei * bi)
// Monero needs not just the nonce over G however, yet also over H
// Then there is a signature (a modified Chaum Pedersen proof) using multiple nonces at once
//
// Accordingly, in order for this library to be robust, it supports generating an arbitrary amount
// of nonces, each against an arbitrary list of generators
//
// Each nonce remains of the form (d, e) and made into a proper nonce with d + (e * b)
// When representations across multiple generators are provided, a DLEq proof is also provided to
// confirm their integrity

use core::ops::Deref;
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use transcript::Transcript;

use ciphersuite::group::{ff::PrimeField, Group, GroupEncoding};
use multiexp::multiexp_vartime;

use dleq::MultiDLEqProof;

use crate::{curve::Curve, Participant};

// Transcript used to aggregate binomial nonces for usage within a single DLEq proof.
fn aggregation_transcript<T: Transcript>(context: &[u8]) -> T {
  let mut transcript = T::new(b"FROST DLEq Aggregation v0.5");
  transcript.append_message(b"context", context);
  transcript
}

// Every participant proves for their commitments at the start of the protocol
// These proofs are verified sequentially, requiring independent transcripts
// In order to make these transcripts more robust, the FROST transcript (at time of preprocess) is
// challenged in order to create a commitment to it, carried in each independent transcript
// (effectively forking the original transcript)
//
// For FROST, as defined by the IETF, this will do nothing (and this transcript will never even be
// constructed). For higher level protocols, the transcript may have contextual info these proofs
// will then be bound to
fn dleq_transcript<T: Transcript>(context: &[u8]) -> T {
  let mut transcript = T::new(b"FROST Commitments DLEq v0.5");
  transcript.append_message(b"context", context);
  transcript
}

// Each nonce is actually a pair of random scalars, notated as d, e under the FROST paper
// This is considered a single nonce as r = d + be
#[derive(Clone, Zeroize)]
pub(crate) struct Nonce<C: Curve>(pub(crate) [Zeroizing<C::F>; 2]);

// Commitments to a specific generator for this binomial nonce
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct GeneratorCommitments<C: Curve>(pub(crate) [C::G; 2]);
impl<C: Curve> GeneratorCommitments<C> {
  fn read<R: Read>(reader: &mut R) -> io::Result<GeneratorCommitments<C>> {
    Ok(GeneratorCommitments([<C as Curve>::read_G(reader)?, <C as Curve>::read_G(reader)?]))
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0[0].to_bytes().as_ref())?;
    writer.write_all(self.0[1].to_bytes().as_ref())
  }
}

// A single nonce's commitments and relevant proofs
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NonceCommitments<C: Curve> {
  // Called generators as these commitments are indexed by generator later on
  // So to get the commitments for the first generator, it'd be commitments.generators[0]
  pub(crate) generators: Vec<GeneratorCommitments<C>>,
}

impl<C: Curve> NonceCommitments<C> {
  pub(crate) fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret_share: &Zeroizing<C::F>,
    generators: &[C::G],
  ) -> (Nonce<C>, NonceCommitments<C>) {
    let nonce = Nonce::<C>([
      C::random_nonce(secret_share, &mut *rng),
      C::random_nonce(secret_share, &mut *rng),
    ]);

    let mut commitments = Vec::with_capacity(generators.len());
    for generator in generators {
      commitments.push(GeneratorCommitments([
        *generator * nonce.0[0].deref(),
        *generator * nonce.0[1].deref(),
      ]));
    }

    (nonce, NonceCommitments { generators: commitments })
  }

  fn read<R: Read>(reader: &mut R, generators: &[C::G]) -> io::Result<NonceCommitments<C>> {
    Ok(NonceCommitments {
      generators: (0 .. generators.len())
        .map(|_| GeneratorCommitments::read(reader))
        .collect::<Result<_, _>>()?,
    })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for generator in &self.generators {
      generator.write(writer)?;
    }
    Ok(())
  }

  fn transcript<T: Transcript>(&self, t: &mut T) {
    t.domain_separate(b"nonce");
    for commitments in &self.generators {
      t.append_message(b"commitment_D", commitments.0[0].to_bytes());
      t.append_message(b"commitment_E", commitments.0[1].to_bytes());
    }
  }

  fn aggregation_factor<T: Transcript>(&self, context: &[u8]) -> C::F {
    let mut transcript = aggregation_transcript::<T>(context);
    self.transcript(&mut transcript);
    <C as Curve>::hash_to_F(b"dleq_aggregation", transcript.challenge(b"binding").as_ref())
  }
}

/// Commitments for all the nonces across all their generators.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Commitments<C: Curve> {
  // Called nonces as these commitments are indexed by nonce
  // So to get the commitments for the first nonce, it'd be commitments.nonces[0]
  pub(crate) nonces: Vec<NonceCommitments<C>>,
  // DLEq Proof proving that each set of commitments were generated using a single pair of discrete
  // logarithms
  pub(crate) dleq: Option<MultiDLEqProof<C::G>>,
}

impl<C: Curve> Commitments<C> {
  pub(crate) fn new<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    secret_share: &Zeroizing<C::F>,
    planned_nonces: &[Vec<C::G>],
    context: &[u8],
  ) -> (Vec<Nonce<C>>, Commitments<C>) {
    let mut nonces = vec![];
    let mut commitments = vec![];

    let mut dleq_generators = vec![];
    let mut dleq_nonces = vec![];
    for generators in planned_nonces {
      let (nonce, these_commitments): (Nonce<C>, _) =
        NonceCommitments::new(&mut *rng, secret_share, generators);

      if generators.len() > 1 {
        dleq_generators.push(generators.clone());
        dleq_nonces.push(Zeroizing::new(
          (these_commitments.aggregation_factor::<T>(context) * nonce.0[1].deref()) +
            nonce.0[0].deref(),
        ));
      }

      nonces.push(nonce);
      commitments.push(these_commitments);
    }

    let dleq = if !dleq_generators.is_empty() {
      Some(MultiDLEqProof::prove(
        rng,
        &mut dleq_transcript::<T>(context),
        &dleq_generators,
        &dleq_nonces,
      ))
    } else {
      None
    };

    (nonces, Commitments { nonces: commitments, dleq })
  }

  pub(crate) fn transcript<T: Transcript>(&self, t: &mut T) {
    t.domain_separate(b"commitments");
    for nonce in &self.nonces {
      nonce.transcript(t);
    }

    // Transcripting the DLEqs implicitly transcripts the exact generators used for the nonces in
    // an exact order
    // This means it shouldn't be possible for variadic generators to cause conflicts
    if let Some(dleq) = &self.dleq {
      t.append_message(b"dleq", dleq.serialize());
    }
  }

  pub(crate) fn read<R: Read, T: Transcript>(
    reader: &mut R,
    generators: &[Vec<C::G>],
    context: &[u8],
  ) -> io::Result<Self> {
    let nonces = (0 .. generators.len())
      .map(|i| NonceCommitments::read(reader, &generators[i]))
      .collect::<Result<Vec<NonceCommitments<C>>, _>>()?;

    let mut dleq_generators = vec![];
    let mut dleq_nonces = vec![];
    for (generators, nonce) in generators.iter().cloned().zip(&nonces) {
      if generators.len() > 1 {
        let binding = nonce.aggregation_factor::<T>(context);
        let mut aggregated = vec![];
        for commitments in &nonce.generators {
          aggregated.push(commitments.0[0] + (commitments.0[1] * binding));
        }
        dleq_generators.push(generators);
        dleq_nonces.push(aggregated);
      }
    }

    let dleq = if !dleq_generators.is_empty() {
      let dleq = MultiDLEqProof::read(reader, dleq_generators.len())?;
      dleq
        .verify(&mut dleq_transcript::<T>(context), &dleq_generators, &dleq_nonces)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid DLEq proof"))?;
      Some(dleq)
    } else {
      None
    };

    Ok(Commitments { nonces, dleq })
  }

  pub(crate) fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for nonce in &self.nonces {
      nonce.write(writer)?;
    }
    if let Some(dleq) = &self.dleq {
      dleq.write(writer)?;
    }
    Ok(())
  }
}

pub(crate) struct IndividualBinding<C: Curve> {
  commitments: Commitments<C>,
  binding_factors: Option<Vec<C::F>>,
}

pub(crate) struct BindingFactor<C: Curve>(pub(crate) HashMap<Participant, IndividualBinding<C>>);

impl<C: Curve> BindingFactor<C> {
  pub(crate) fn insert(&mut self, i: Participant, commitments: Commitments<C>) {
    self.0.insert(i, IndividualBinding { commitments, binding_factors: None });
  }

  pub(crate) fn calculate_binding_factors<T: Clone + Transcript>(&mut self, transcript: &T) {
    for (l, binding) in self.0.iter_mut() {
      let mut transcript = transcript.clone();
      transcript.append_message(b"participant", C::F::from(u64::from(u16::from(*l))).to_repr());
      // It *should* be perfectly fine to reuse a binding factor for multiple nonces
      // This generates a binding factor per nonce just to ensure it never comes up as a question
      binding.binding_factors = Some(
        (0 .. binding.commitments.nonces.len())
          .map(|_| C::hash_binding_factor(transcript.challenge(b"rho").as_ref()))
          .collect(),
      );
    }
  }

  pub(crate) fn binding_factors(&self, i: Participant) -> &[C::F] {
    self.0[&i].binding_factors.as_ref().unwrap()
  }

  // Get the bound nonces for a specific party
  pub(crate) fn bound(&self, l: Participant) -> Vec<Vec<C::G>> {
    let mut res = vec![];
    for (i, (nonce, rho)) in
      self.0[&l].commitments.nonces.iter().zip(self.binding_factors(l).iter()).enumerate()
    {
      res.push(vec![]);
      for generator in &nonce.generators {
        res[i].push(generator.0[0] + (generator.0[1] * rho));
      }
    }
    res
  }

  // Get the nonces for this signing session
  pub(crate) fn nonces(&self, planned_nonces: &[Vec<C::G>]) -> Vec<Vec<C::G>> {
    let mut nonces = Vec::with_capacity(planned_nonces.len());
    for n in 0 .. planned_nonces.len() {
      nonces.push(Vec::with_capacity(planned_nonces[n].len()));
      for g in 0 .. planned_nonces[n].len() {
        #[allow(non_snake_case)]
        let mut D = C::G::identity();
        let mut statements = Vec::with_capacity(self.0.len());
        #[allow(non_snake_case)]
        for IndividualBinding { commitments, binding_factors } in self.0.values() {
          D += commitments.nonces[n].generators[g].0[0];
          statements
            .push((binding_factors.as_ref().unwrap()[n], commitments.nonces[n].generators[g].0[1]));
        }
        nonces[n].push(D + multiexp_vartime(&statements));
      }
    }
    nonces
  }
}
