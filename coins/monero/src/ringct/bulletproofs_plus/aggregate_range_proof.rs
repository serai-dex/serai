use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use multiexp::{multiexp, multiexp_vartime, BatchVerifier};
use group::{ff::Field, Group, GroupEncoding};
use dalek_ff_group::{Scalar, EdwardsPoint};
use ciphersuite::{Ciphersuite, Ed25519};

use crate::{
  Commitment,
  ringct::bulletproofs_plus::{
    RANGE_PROOF_BITS, ScalarVector, PointVector, GeneratorsList, Generators,
    weighted_inner_product::{WipStatement, WipWitness, WipProof},
    u64_decompose,
  },
};

const N: usize = RANGE_PROOF_BITS;

// Figure 3
#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement {
  generators: Generators,
  V: PointVector,
}

impl Zeroize for AggregateRangeStatement {
  fn zeroize(&mut self) {
    self.V.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AggregateRangeWitness {
  values: Vec<u64>,
  gammas: Vec<Scalar>,
}

impl AggregateRangeWitness {
  pub(crate) fn new(commitments: &[Commitment]) -> Option<Self> {
    if commitments.is_empty() || (commitments.len() > MAX_M) {
      return None;
    }

    let mut values = Vec::with_capacity(commitments.len());
    let mut gammas = Vec::with_capacity(commitments.len());
    for commitment in commitments {
      values.push(commitment.amount);
      gammas.push(Scalar(commitment.mask));
    }
    AggregateRangeWitness { values, gammas }
  }
}

#[derive(Clone, Debug, Zeroize)]
pub(crate) struct AggregateRangeProof {
  A: EdwardsPoint,
  wip: WipProof,
}

impl AggregateRangeStatement {
  pub(crate) fn new(generators: Generators, V: Vec<EdwardsPoint>) -> Self {
    assert!(!V.is_empty());
    Self { generators, V: PointVector(V) }
  }

  fn transcript_A<T: Transcript>(transcript: &mut T, A: EdwardsPoint) -> (Scalar, Scalar) {
    transcript.append_message(b"A", A.to_bytes());

    let y = Ed25519::hash_to_F(b"aggregate_range_proof", transcript.challenge(b"y").as_ref());
    if bool::from(y.is_zero()) {
      panic!("zero challenge in aggregate range proof");
    }

    let z = Ed25519::hash_to_F(b"aggregate_range_proof", transcript.challenge(b"z").as_ref());
    if bool::from(z.is_zero()) {
      panic!("zero challenge in aggregate range proof");
    }

    (y, z)
  }

  fn d_j(j: usize, m: usize) -> ScalarVector {
    let mut d_j = Vec::with_capacity(m * RANGE_PROOF_BITS);
    for _ in 0 .. (j - 1) * N {
      d_j.push(Scalar::ZERO);
    }
    d_j.append(&mut ScalarVector::powers(Scalar::from(2u8), RANGE_PROOF_BITS).0);
    for _ in 0 .. (m - j) * N {
      d_j.push(Scalar::ZERO);
    }
    ScalarVector(d_j)
  }

  fn compute_A_hat<T: Transcript>(
    V: &PointVector,
    generators: &Generators,
    transcript: &mut T,
    A: EdwardsPoint,
  ) -> (Scalar, ScalarVector, Scalar, Scalar, ScalarVector, EdwardsPoint) {
    // TODO: First perform the WIP transcript before acquiring challenges
    let (y, z) = Self::transcript_A(transcript, A);

    let mn = V.len() * N;

    let mut z_pow = Vec::with_capacity(V.len());

    let mut d = ScalarVector::new(mn);
    for j in 1 ..= V.len() {
      z_pow.push(z.pow(Scalar::from(2 * u64::try_from(j).unwrap()))); // TODO: Optimize this
      d = d.add_vec(&Self::d_j(j, V.len()).mul(z_pow[j - 1]));
    }

    let mut ascending_y = ScalarVector(vec![y]);
    for i in 1 .. mn {
      ascending_y.0.push(ascending_y[i - 1] * y);
    }
    let y_pows = ascending_y.clone().sum();

    let mut descending_y = ascending_y.clone();
    descending_y.0.reverse();

    let d_descending_y = d.mul_vec(&descending_y);

    let y_mn_plus_one = descending_y[0] * y;
    debug_assert_eq!(y_mn_plus_one, y.pow(Scalar::from(u64::try_from(mn).unwrap() + 1)));

    let mut commitment_accum = EdwardsPoint::identity();
    for (j, commitment) in V.0.iter().enumerate() {
      commitment_accum += *commitment * z_pow[j];
    }

    let neg_z = -z;
    let mut A_terms = Vec::with_capacity((generators.len() * 2) + 2);
    for (i, d_y_z) in d_descending_y.add(z).0.drain(..).enumerate() {
      A_terms.push((neg_z, generators.generator(GeneratorsList::GBold1, i)));
      A_terms.push((d_y_z, generators.generator(GeneratorsList::HBold1, i)));
    }
    A_terms.push((y_mn_plus_one, commitment_accum));
    A_terms.push((
      ((y_pows * z) - (d.sum() * y_mn_plus_one * z) - (y_pows * z.square())),
      generators.g(),
    ));

    (y, d_descending_y, y_mn_plus_one, z, ScalarVector(z_pow), A + multiexp_vartime(&A_terms))
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Transcript>(
    self,
    rng: &mut R,
    transcript: &mut T,
    witness: AggregateRangeWitness,
  ) -> AggregateRangeProof {
    assert_eq!(self.V.len(), witness.values.len());
    debug_assert_eq!(witness.values.len(), witness.gammas.len());
    for (commitment, (value, gamma)) in
      self.V.0.iter().zip(witness.values.iter().zip(witness.gammas.iter()))
    {
      debug_assert_eq!(Commitment::new(**gamma, *value).calculate(), **commitment);
    }

    let transcript = initial_transcript(self.V.clone());

    let Self { generators, V } = self;
    let generators = generators.reduce(V.len() * RANGE_PROOF_BITS);

    let mut d_js = Vec::with_capacity(V.len());
    let mut a_l = ScalarVector(Vec::with_capacity(V.len() * RANGE_PROOF_BITS));
    for j in 1 ..= V.len() {
      d_js.push(Self::d_j(j, V.len()));
      a_l.0.append(&mut u64_decompose(witness.values[j - 1]).0);
    }

    for (value, d_j) in witness.values.iter().zip(d_js.iter()) {
      debug_assert_eq!(d_j.len(), a_l.len());
      debug_assert_eq!(a_l.inner_product(d_j), Scalar::from(*value));
    }

    let a_r = a_l.sub(Scalar::ONE);

    let alpha = Scalar::random(&mut *rng);

    let mut A_terms = Vec::with_capacity((generators.len() * 2) + 1);
    for (i, a_l) in a_l.0.iter().enumerate() {
      A_terms.push((*a_l, generators.generator(GeneratorsList::GBold1, i)));
    }
    for (i, a_r) in a_r.0.iter().enumerate() {
      A_terms.push((*a_r, generators.generator(GeneratorsList::HBold1, i)));
    }
    A_terms.push((alpha, generators.h()));
    let A = multiexp(&A_terms);
    A_terms.zeroize();

    let (y, d_descending_y, y_mn_plus_one, z, z_pow, A_hat) =
      Self::compute_A_hat(&V, &generators, transcript, A);

    let a_l = a_l.sub(z);
    let a_r = a_r.add_vec(&d_descending_y).add(z);
    let mut alpha = alpha;
    for j in 1 ..= witness.gammas.len() {
      alpha += z_pow[j - 1] * witness.gammas[j - 1] * y_mn_plus_one;
    }

    AggregateRangeProof {
      A,
      wip: WipStatement::new(generators, A_hat, y).prove(
        rng,
        transcript,
        WipWitness::new(a_l, a_r, alpha),
      ),
    }
  }

  pub(crate) fn verify<R: RngCore + CryptoRng, T: Transcript>(
    self,
    rng: &mut R,
    verifier: &mut BatchVerifier<(), EdwardsPoint>,
    transcript: &mut T,
    proof: AggregateRangeProof,
  ) {
    let transcript = initial_transcript(self.V.clone());

    let Self { generators, V } = self;
    let generators = generators.reduce(V.len() * RANGE_PROOF_BITS);

    let (y, _, _, _, _, A_hat) = Self::compute_A_hat(&V, &generators, transcript, proof.A);
    (WipStatement::new(generators, A_hat, y)).verify(rng, verifier, transcript, proof.wip);
  }
}
