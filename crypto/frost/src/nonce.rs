// FROST defines its nonce as sum(Di, Ei * bi)
// Monero needs not just the nonce over G however, yet also over H
// Then there is a signature (a modified Chaum Pedersen proof) using multiple nonces at once
//
// Accordingly, in order for this library to be robust, it supports generating an arbitrary amount
// of nonces, each against an arbitrary list of basepoints
//
// Each nonce remains of the form (d, e) and made into a proper nonce with d + (e * b)
// When multiple D, E pairs are provided, a DLEq proof is also provided to confirm their integrity

use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use group::{ff::PrimeField, Group, GroupEncoding};
use multiexp::multiexp_vartime;

use dleq::DLEqProof;

use crate::curve::Curve;

fn dleq_transcript<T: Transcript>() -> T {
  T::new(b"FROST_nonce_dleq")
}

// Each nonce is actually a pair of random scalars, notated as d, e under the FROST paper
// This is considered a single nonce as r = d + be
#[derive(Clone, Zeroize)]
pub(crate) struct Nonce<C: Curve>(pub(crate) [C::F; 2]);

// Commitments to a specific generator for this nonce
#[derive(Copy, Clone, PartialEq, Eq, Zeroize)]
pub(crate) struct GeneratorCommitments<C: Curve>(pub(crate) [C::G; 2]);
impl<C: Curve> GeneratorCommitments<C> {
  fn read<R: Read>(reader: &mut R) -> io::Result<GeneratorCommitments<C>> {
    Ok(GeneratorCommitments([C::read_G(reader)?, C::read_G(reader)?]))
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0[0].to_bytes().as_ref())?;
    writer.write_all(self.0[1].to_bytes().as_ref())
  }
}

// A single nonce's commitments and relevant proofs
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub(crate) struct NonceCommitments<C: Curve> {
  // Called generators as these commitments are indexed by generator
  pub(crate) generators: Vec<GeneratorCommitments<C>>,
  // DLEq Proofs proving that these commitments are generated using the same scalar pair
  // This could be further optimized with a multi-nonce proof, offering just one proof for all
  // nonces. See https://github.com/serai-dex/serai/issues/38
  // TODO
  pub(crate) dleqs: Option<[DLEqProof<C::G>; 2]>,
}

impl<C: Curve> NonceCommitments<C> {
  pub(crate) fn new<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    mut secret_share: C::F,
    generators: &[C::G],
  ) -> (Nonce<C>, NonceCommitments<C>) {
    let nonce =
      Nonce([C::random_nonce(secret_share, &mut *rng), C::random_nonce(secret_share, &mut *rng)]);
    secret_share.zeroize();

    let mut commitments = Vec::with_capacity(generators.len());
    for generator in generators {
      commitments.push(GeneratorCommitments([*generator * nonce.0[0], *generator * nonce.0[1]]));
    }

    let mut dleqs = None;
    if generators.len() >= 2 {
      let mut dleq = |nonce| {
        // Uses an independent transcript as each signer must prove this with their commitments,
        // yet they're validated while processing everyone's data sequentially, by the global order
        // This avoids needing to clone and fork the transcript around
        // TODO: At least include a challenge from the existing transcript
        DLEqProof::prove(&mut *rng, &mut dleq_transcript::<T>(), generators, nonce)
      };
      dleqs = Some([dleq(nonce.0[0]), dleq(nonce.0[1])]);
    }

    (nonce, NonceCommitments { generators: commitments, dleqs })
  }

  fn read<R: Read, T: Transcript>(
    reader: &mut R,
    generators: &[C::G],
  ) -> io::Result<NonceCommitments<C>> {
    let commitments: Vec<GeneratorCommitments<C>> = (0 .. generators.len())
      .map(|_| GeneratorCommitments::read(reader))
      .collect::<Result<_, _>>()?;

    let mut dleqs = None;
    if generators.len() >= 2 {
      let mut verify = |i| -> io::Result<_> {
        let dleq = DLEqProof::deserialize(reader)?;
        dleq
          .verify(
            &mut dleq_transcript::<T>(),
            &generators,
            &commitments.iter().map(|commitments| commitments.0[i]).collect::<Vec<_>>(),
          )
          .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid DLEq proof"))?;
        Ok(dleq)
      };
      dleqs = Some([verify(0)?, verify(1)?]);
    }

    Ok(NonceCommitments { generators: commitments, dleqs })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for generator in &self.generators {
      generator.write(writer)?;
    }
    if let Some(dleqs) = &self.dleqs {
      dleqs[0].serialize(writer)?;
      dleqs[1].serialize(writer)?;
    }
    Ok(())
  }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub(crate) struct Commitments<C: Curve> {
  // Called nonces as these commitments are indexed by nonce
  pub(crate) nonces: Vec<NonceCommitments<C>>,
}

impl<C: Curve> Commitments<C> {
  pub(crate) fn new<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    secret_share: C::F,
    planned_nonces: &[Vec<C::G>],
  ) -> (Vec<Nonce<C>>, Commitments<C>) {
    let mut nonces = vec![];
    let mut commitments = vec![];
    for generators in planned_nonces {
      let (nonce, these_commitments) =
        NonceCommitments::new::<_, T>(&mut *rng, secret_share, generators);
      nonces.push(nonce);
      commitments.push(these_commitments);
    }
    (nonces, Commitments { nonces: commitments })
  }

  pub(crate) fn transcript<T: Transcript>(&self, t: &mut T) {
    for nonce in &self.nonces {
      for commitments in &nonce.generators {
        t.append_message(b"commitment_D", commitments.0[0].to_bytes().as_ref());
        t.append_message(b"commitment_E", commitments.0[1].to_bytes().as_ref());
      }

      // Transcripting the DLEqs implicitly transcripts the exact generators used for this nonce
      // This means it shouldn't be possible for variadic generators to cause conflicts as they're
      // committed to as their entire series per-nonce, not as isolates
      if let Some(dleqs) = &nonce.dleqs {
        let mut transcript_dleq = |label, dleq: &DLEqProof<C::G>| {
          let mut buf = Vec::with_capacity(C::G_len() + C::F_len());
          dleq.serialize(&mut buf).unwrap();
          t.append_message(label, &buf);
        };
        transcript_dleq(b"dleq_D", &dleqs[0]);
        transcript_dleq(b"dleq_E", &dleqs[1]);
      }
    }
  }

  pub(crate) fn read<R: Read, T: Transcript>(
    reader: &mut R,
    nonces: &[Vec<C::G>],
  ) -> io::Result<Self> {
    Ok(Commitments {
      nonces: (0 .. nonces.len())
        .map(|i| NonceCommitments::read::<_, T>(reader, &nonces[i]))
        .collect::<Result<_, _>>()?,
    })
  }

  pub(crate) fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for nonce in &self.nonces {
      nonce.write(writer)?;
    }
    Ok(())
  }
}

pub(crate) struct BindingFactor<C: Curve>(
  pub(crate) HashMap<u16, (Commitments<C>, Option<Vec<C::F>>)>,
);

impl<C: Curve> Zeroize for BindingFactor<C> {
  fn zeroize(&mut self) {
    for (mut validator, mut commitments) in self.0.drain() {
      validator.zeroize();
      commitments.0.zeroize();
      commitments.1.zeroize();
    }
  }
}

impl<C: Curve> BindingFactor<C> {
  pub(crate) fn insert(&mut self, i: u16, commitments: Commitments<C>) {
    self.0.insert(i, (commitments, None));
  }

  pub(crate) fn calculate_binding_factors<T: Clone + Transcript>(&mut self, transcript: &mut T) {
    for (l, commitments) in self.0.iter_mut() {
      let mut transcript = transcript.clone();
      transcript.append_message(b"participant", C::F::from(u64::from(*l)).to_repr().as_ref());
      // It *should* be perfectly fine to reuse a binding factor for multiple nonces
      // This generates a binding factor per nonce just to ensure it never comes up as a question
      commitments.1 = Some(
        (0 .. commitments.0.nonces.len())
          .map(|_| C::hash_binding_factor(transcript.challenge(b"rho").as_ref()))
          .collect(),
      );
    }
  }

  pub(crate) fn binding_factors(&self, i: u16) -> &[C::F] {
    self.0[&i].1.as_ref().unwrap()
  }

  // Get the bound nonces for a specific party
  pub(crate) fn bound(&self, l: u16) -> Vec<Vec<C::G>> {
    let mut res = vec![];
    for (i, (nonce, rho)) in
      self.0[&l].0.nonces.iter().zip(self.binding_factors(l).iter()).enumerate()
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
        for (commitments, binding) in self.0.values() {
          D += commitments.nonces[n].generators[g].0[0];
          statements.push((binding.clone().unwrap()[n], commitments.nonces[n].generators[g].0[1]));
        }
        nonces[n].push(D + multiexp_vartime(&statements));
      }
    }
    nonces
  }
}
