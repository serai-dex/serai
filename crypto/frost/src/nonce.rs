// FROST defines its nonce as sum(Di, Ei * bi)
//
// In order for this library to be robust, it supports generating an arbitrary amount of nonces,
// each against an arbitrary list of generators
//
// Each nonce remains of the form (d, e) and made into a proper nonce with d + (e * b)

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

use crate::{curve::Curve, Participant};

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

// A single nonce's commitments
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
}

/// Commitments for all the nonces across all their generators.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Commitments<C: Curve> {
  // Called nonces as these commitments are indexed by nonce
  // So to get the commitments for the first nonce, it'd be commitments.nonces[0]
  pub(crate) nonces: Vec<NonceCommitments<C>>,
}

impl<C: Curve> Commitments<C> {
  pub(crate) fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret_share: &Zeroizing<C::F>,
    planned_nonces: &[Vec<C::G>],
  ) -> (Vec<Nonce<C>>, Commitments<C>) {
    let mut nonces = vec![];
    let mut commitments = vec![];

    for generators in planned_nonces {
      let (nonce, these_commitments): (Nonce<C>, _) =
        NonceCommitments::new(&mut *rng, secret_share, generators);

      nonces.push(nonce);
      commitments.push(these_commitments);
    }

    (nonces, Commitments { nonces: commitments })
  }

  pub(crate) fn transcript<T: Transcript>(&self, t: &mut T) {
    t.domain_separate(b"commitments");
    for nonce in &self.nonces {
      nonce.transcript(t);
    }
  }

  pub(crate) fn read<R: Read>(reader: &mut R, generators: &[Vec<C::G>]) -> io::Result<Self> {
    let nonces = (0 .. generators.len())
      .map(|i| NonceCommitments::read(reader, &generators[i]))
      .collect::<Result<Vec<NonceCommitments<C>>, _>>()?;

    Ok(Commitments { nonces })
  }

  pub(crate) fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for nonce in &self.nonces {
      nonce.write(writer)?;
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
    for (l, binding) in &mut self.0 {
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
