use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use multiexp::{multiexp, multiexp_vartime, Point as MultiexpPoint, BatchVerifier};
use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite,
};

use crate::{
  RANGE_PROOF_BITS, ScalarVector, GeneratorsList, ProofGenerators, InnerProductGenerators,
  RangeCommitment,
  weighted_inner_product::{WipStatement, WipWitness, WipProof},
  u64_decompose,
};

// Figure 2
#[derive(Clone, Debug)]
pub struct SingleRangeStatement<'a, T: 'static + Transcript, C: Ciphersuite> {
  generators: ProofGenerators<'a, T, C>,
  V: C::G,
}

impl<'a, T: 'static + Transcript, C: Ciphersuite> Zeroize for SingleRangeStatement<'a, T, C> {
  fn zeroize(&mut self) {
    self.V.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SingleRangeWitness<C: Ciphersuite> {
  value: u64,
  gamma: C::F,
}

impl<C: Ciphersuite> SingleRangeWitness<C> {
  pub fn new(commitment: RangeCommitment<C>) -> Self {
    SingleRangeWitness { value: commitment.value, gamma: commitment.mask }
  }
}

#[derive(Clone, Debug, Zeroize)]
pub struct SingleRangeProof<C: Ciphersuite> {
  A: C::G,
  wip: WipProof<C>,
}

impl<'a, T: 'static + Transcript, C: Ciphersuite> SingleRangeStatement<'a, T, C> {
  pub fn new(generators: ProofGenerators<'a, T, C>, V: C::G) -> Self {
    Self { generators, V }
  }

  fn initial_transcript(&self, transcript: &mut T) {
    transcript.domain_separate(b"single_range_proof");
    transcript.append_message(b"commitment", self.V.to_bytes());
  }

  fn transcript_A(transcript: &mut T, A: C::G) -> (C::F, C::F) {
    transcript.append_message(b"A", A.to_bytes());

    let y = C::hash_to_F(b"single_range_proof", transcript.challenge(b"y").as_ref());
    if bool::from(y.is_zero()) {
      panic!("zero challenge in single range proof");
    }

    let z = C::hash_to_F(b"single_range_proof", transcript.challenge(b"z").as_ref());
    if bool::from(z.is_zero()) {
      panic!("zero challenge in single range proof");
    }

    (y, z)
  }

  fn A_hat<GB: Clone + AsRef<[MultiexpPoint<C::G>]>>(
    transcript: &mut T,
    generators: &InnerProductGenerators<'a, T, C, GB>,
    V: C::G,
    A: C::G,
  ) -> (C::F, ScalarVector<C>, C::F, C::F, C::G) {
    // TODO: First perform the WIP transcript before acquiring challenges
    let (y, z) = Self::transcript_A(transcript, A);

    let two_pows = ScalarVector::powers(C::F::from(2), RANGE_PROOF_BITS);

    let mut ascending_y = ScalarVector(Vec::with_capacity(RANGE_PROOF_BITS));
    ascending_y.0.push(y);
    for i in 1 .. RANGE_PROOF_BITS {
      ascending_y.0.push(ascending_y[i - 1] * y);
    }

    let mut descending_y = ascending_y.clone();
    descending_y.0.reverse();

    let y_n_plus_one = descending_y[0] * y;
    debug_assert_eq!(y_n_plus_one, y.pow([u64::try_from(RANGE_PROOF_BITS).unwrap() + 1]));
    let y_pows = ascending_y.sum();

    let two_descending_y = two_pows.mul_vec(&descending_y);
    let mut A_terms = Vec::with_capacity((generators.len() * 2) + 2);
    let neg_z = -z;
    for (i, scalar) in two_descending_y.add(z).0.drain(..).enumerate() {
      A_terms.push((neg_z, generators.generator(GeneratorsList::GBold1, i).point()));
      A_terms.push((scalar, generators.generator(GeneratorsList::HBold1, i).point()));
    }
    A_terms.push((y_n_plus_one, V));
    A_terms.push((
      (y_pows * z) - (two_pows.sum() * y_n_plus_one * z) - (y_pows * z.square()),
      generators.g().point(),
    ));
    (y, two_descending_y, y_n_plus_one, z, A + multiexp_vartime(&A_terms))
  }

  pub fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    transcript: &mut T,
    witness: SingleRangeWitness<C>,
  ) -> SingleRangeProof<C> {
    self.initial_transcript(transcript);

    let Self { generators, V } = self;
    let generators = generators.reduce(64, false);
    debug_assert_eq!(
      RangeCommitment::<C>::new(witness.value, witness.gamma)
        .calculate(generators.g().point(), generators.h().point()),
      V
    );

    let alpha = C::F::random(&mut *rng);
    let a_l = u64_decompose::<C>(witness.value);
    debug_assert_eq!(
      a_l.inner_product(&ScalarVector::powers(C::F::from(2), RANGE_PROOF_BITS)),
      C::F::from(witness.value),
    );
    let a_r = a_l.sub(C::F::ONE);
    debug_assert!(bool::from(a_l.inner_product(&a_r).is_zero()));

    let mut A_terms = vec![];
    for (i, a_l) in a_l.0.iter().enumerate() {
      A_terms.push((*a_l, generators.generator(GeneratorsList::GBold1, i).point()));
    }
    for (i, a_r) in a_r.0.iter().enumerate() {
      A_terms.push((*a_r, generators.generator(GeneratorsList::HBold1, i).point()));
    }
    A_terms.push((alpha, generators.h().point()));
    let A = multiexp(&A_terms);
    A_terms.zeroize();
    let (y, two_descending_y, y_n_plus_one, z, A_hat) = Self::A_hat(transcript, &generators, V, A);

    let a_l = a_l.sub(z);
    let a_r = a_r.add_vec(&two_descending_y).add(z);
    let alpha = alpha + (witness.gamma * y_n_plus_one);

    SingleRangeProof {
      A,
      wip: WipStatement::new(&generators, A_hat, y).prove(
        rng,
        transcript,
        WipWitness::new(a_l, a_r, alpha),
      ),
    }
  }

  pub fn verify<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BatchVerifier<(), C::G>,
    transcript: &mut T,
    proof: SingleRangeProof<C>,
  ) {
    self.initial_transcript(transcript);

    let Self { generators, V } = self;
    let generators = generators.reduce(64, false);
    let (y, _, _, _, A_hat) = Self::A_hat(transcript, &generators, V, proof.A);
    (WipStatement::new(&generators, A_hat, y)).verify(rng, verifier, transcript, proof.wip);
  }
}
