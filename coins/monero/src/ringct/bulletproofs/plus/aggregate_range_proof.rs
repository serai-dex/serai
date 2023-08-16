use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use multiexp::{multiexp, multiexp_vartime, BatchVerifier};
use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use dalek_ff_group::{Scalar, EdwardsPoint};

use crate::{
  Commitment,
  ringct::{
    bulletproofs::core::{MAX_M, N},
    bulletproofs::plus::{
      ScalarVector, PointVector, GeneratorsList, Generators,
      transcript::*,
      weighted_inner_product::{WipStatement, WipWitness, WipProof},
      padded_pow_of_2, u64_decompose,
    },
  },
};

// Figure 3
#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement {
  generators: Generators,
  V: Vec<EdwardsPoint>,
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
    Some(AggregateRangeWitness { values, gammas })
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRangeProof {
  pub(crate) A: EdwardsPoint,
  pub(crate) wip: WipProof,
}

impl AggregateRangeStatement {
  pub(crate) fn new(V: Vec<EdwardsPoint>) -> Option<Self> {
    if V.is_empty() || (V.len() > MAX_M) {
      return None;
    }

    Some(Self { generators: Generators::new(), V })
  }

  fn transcript_A(transcript: &mut Scalar, A: EdwardsPoint) -> (Scalar, Scalar) {
    let y = hash_to_scalar(&[transcript.to_repr().as_ref(), A.to_bytes().as_ref()].concat());
    let z = hash_to_scalar(y.to_bytes().as_ref());
    *transcript = z;
    (y, z)
  }

  fn d_j(j: usize, m: usize) -> ScalarVector {
    let mut d_j = Vec::with_capacity(m * N);
    for _ in 0 .. (j - 1) * N {
      d_j.push(Scalar::ZERO);
    }
    d_j.append(&mut ScalarVector::powers(Scalar::from(2u8), N).0);
    for _ in 0 .. (m - j) * N {
      d_j.push(Scalar::ZERO);
    }
    ScalarVector(d_j)
  }

  fn compute_A_hat(
    mut V: PointVector,
    generators: &Generators,
    transcript: &mut Scalar,
    mut A: EdwardsPoint,
  ) -> (Scalar, ScalarVector, Scalar, Scalar, ScalarVector, EdwardsPoint) {
    let (y, z) = Self::transcript_A(transcript, A);
    A = A.mul_by_cofactor();

    while V.len() < padded_pow_of_2(V.len()) {
      V.0.push(EdwardsPoint::identity());
    }
    let mn = V.len() * N;

    let mut z_pow = Vec::with_capacity(V.len());

    let mut d = ScalarVector::new(mn);
    for j in 1 ..= V.len() {
      z_pow.push(z.pow(Scalar::from(2 * u64::try_from(j).unwrap()))); // TODO: Optimize this
      d = d.add_vec(&Self::d_j(j, V.len()).mul(z_pow[j - 1]));
    }

    let mut ascending_y = ScalarVector(vec![y]);
    for i in 1 .. d.len() {
      ascending_y.0.push(ascending_y[i - 1] * y);
    }
    let y_pows = ascending_y.clone().sum();

    let mut descending_y = ascending_y.clone();
    descending_y.0.reverse();

    let d_descending_y = d.mul_vec(&descending_y);

    let y_mn_plus_one = descending_y[0] * y;

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

  pub(crate) fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    witness: AggregateRangeWitness,
  ) -> Option<AggregateRangeProof> {
    // Check for consistency with the witness
    if self.V.len() != witness.values.len() {
      return None;
    }
    for (commitment, (value, gamma)) in
      self.V.iter().zip(witness.values.iter().zip(witness.gammas.iter()))
    {
      if Commitment::new(**gamma, *value).calculate() != **commitment {
        return None;
      }
    }

    let Self { generators, V } = self;
    // Monero expects all of these points to be torsion-free
    // Generally, for Bulletproofs, it sends points * INV_EIGHT and then performs a torsion clear
    // by multiplying by 8
    // This also restores the original value due to the preprocessing
    // Commitments aren't transmitted INV_EIGHT though, so this multiplies by INV_EIGHT to enable
    // clearing its cofactor without mutating the value
    // For some reason, these values are transcripted * INV_EIGHT, not as transmitted
    let mut V = V.into_iter().map(|V| EdwardsPoint(V.0 * crate::INV_EIGHT())).collect::<Vec<_>>();
    let mut transcript = initial_transcript(V.iter());
    V.iter_mut().for_each(|V| *V = V.mul_by_cofactor());

    // Pad V
    while V.len() < padded_pow_of_2(V.len()) {
      V.push(EdwardsPoint::identity());
    }

    let generators = generators.reduce(V.len() * N);

    let mut d_js = Vec::with_capacity(V.len());
    let mut a_l = ScalarVector(Vec::with_capacity(V.len() * N));
    for j in 1 ..= V.len() {
      d_js.push(Self::d_j(j, V.len()));
      a_l.0.append(&mut u64_decompose(*witness.values.get(j - 1).unwrap_or(&0)).0);
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
    let mut A = multiexp(&A_terms);
    A_terms.zeroize();

    // Multiply by INV_EIGHT per earlier commentary
    A.0 *= crate::INV_EIGHT();

    let (y, d_descending_y, y_mn_plus_one, z, z_pow, A_hat) =
      Self::compute_A_hat(PointVector(V), &generators, &mut transcript, A);

    let a_l = a_l.sub(z);
    let a_r = a_r.add_vec(&d_descending_y).add(z);
    let mut alpha = alpha;
    for j in 1 ..= witness.gammas.len() {
      alpha += z_pow[j - 1] * witness.gammas[j - 1] * y_mn_plus_one;
    }

    Some(AggregateRangeProof {
      A,
      wip: WipStatement::new(generators, A_hat, y)
        .prove(rng, transcript, WipWitness::new(a_l, a_r, alpha).unwrap())
        .unwrap(),
    })
  }

  pub(crate) fn verify<Id: Copy + Zeroize, R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BatchVerifier<Id, EdwardsPoint>,
    id: Id,
    proof: AggregateRangeProof,
  ) -> bool {
    let Self { generators, V } = self;

    let mut V = V.into_iter().map(|V| EdwardsPoint(V.0 * crate::INV_EIGHT())).collect::<Vec<_>>();
    let mut transcript = initial_transcript(V.iter());
    V.iter_mut().for_each(|V| *V = V.mul_by_cofactor());

    let generators = generators.reduce(V.len() * N);

    let (y, _, _, _, _, A_hat) =
      Self::compute_A_hat(PointVector(V), &generators, &mut transcript, proof.A);
    WipStatement::new(generators, A_hat, y).verify(rng, verifier, id, transcript, proof.wip)
  }
}
