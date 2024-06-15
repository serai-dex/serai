use std_shims::{vec, vec::Vec};

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{traits::Identity, scalar::Scalar, edwards::EdwardsPoint};

use monero_primitives::{INV_EIGHT, Commitment, keccak256_to_scalar};

use crate::{
  batch_verifier::BulletproofsPlusBatchVerifier,
  core::{MAX_M, N, multiexp, multiexp_vartime},
  plus::{
    ScalarVector, PointVector, GeneratorsList, BpPlusGenerators,
    transcript::*,
    weighted_inner_product::{WipStatement, WipWitness, WipProof},
    padded_pow_of_2, u64_decompose,
  },
};

// Figure 3 of the Bulletproofs+ Paper
#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement {
  generators: BpPlusGenerators,
  V: Vec<EdwardsPoint>,
}

impl Zeroize for AggregateRangeStatement {
  fn zeroize(&mut self) {
    self.V.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AggregateRangeWitness(Vec<Commitment>);

impl AggregateRangeWitness {
  pub(crate) fn new(commitments: Vec<Commitment>) -> Option<Self> {
    if commitments.is_empty() || (commitments.len() > MAX_M) {
      return None;
    }

    Some(AggregateRangeWitness(commitments))
  }
}

/// Internal structure representing a Bulletproof+, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRangeProof {
  pub(crate) A: EdwardsPoint,
  pub(crate) wip: WipProof,
}

struct AHatComputation {
  y: Scalar,
  d_descending_y_plus_z: ScalarVector,
  y_mn_plus_one: Scalar,
  z: Scalar,
  z_pow: ScalarVector,
  A_hat: EdwardsPoint,
}

impl AggregateRangeStatement {
  pub(crate) fn new(V: Vec<EdwardsPoint>) -> Option<Self> {
    if V.is_empty() || (V.len() > MAX_M) {
      return None;
    }

    Some(Self { generators: BpPlusGenerators::new(), V })
  }

  fn transcript_A(transcript: &mut Scalar, A: EdwardsPoint) -> (Scalar, Scalar) {
    let y = keccak256_to_scalar(
      [transcript.to_bytes().as_ref(), A.compress().to_bytes().as_ref()].concat(),
    );
    let z = keccak256_to_scalar(y.to_bytes().as_ref());
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
    generators: &BpPlusGenerators,
    transcript: &mut Scalar,
    mut A: EdwardsPoint,
  ) -> AHatComputation {
    let (y, z) = Self::transcript_A(transcript, A);
    A = A.mul_by_cofactor();

    while V.len() < padded_pow_of_2(V.len()) {
      V.0.push(EdwardsPoint::identity());
    }
    let mn = V.len() * N;

    // 2, 4, 6, 8... powers of z, of length equivalent to the amount of commitments
    let mut z_pow = Vec::with_capacity(V.len());
    // z**2
    z_pow.push(z * z);

    let mut d = ScalarVector::new(mn);
    for j in 1 ..= V.len() {
      z_pow.push(*z_pow.last().unwrap() * z_pow[0]);
      d = d + &(Self::d_j(j, V.len()) * (z_pow[j - 1]));
    }

    let mut ascending_y = ScalarVector(vec![y]);
    for i in 1 .. d.len() {
      ascending_y.0.push(ascending_y[i - 1] * y);
    }
    let y_pows = ascending_y.clone().sum();

    let mut descending_y = ascending_y.clone();
    descending_y.0.reverse();

    let d_descending_y = d.clone() * &descending_y;
    let d_descending_y_plus_z = d_descending_y + z;

    let y_mn_plus_one = descending_y[0] * y;

    let mut commitment_accum = EdwardsPoint::identity();
    for (j, commitment) in V.0.iter().enumerate() {
      commitment_accum += *commitment * z_pow[j];
    }

    let neg_z = -z;
    let mut A_terms = Vec::with_capacity((generators.len() * 2) + 2);
    for (i, d_y_z) in d_descending_y_plus_z.0.iter().enumerate() {
      A_terms.push((neg_z, generators.generator(GeneratorsList::GBold, i)));
      A_terms.push((*d_y_z, generators.generator(GeneratorsList::HBold, i)));
    }
    A_terms.push((y_mn_plus_one, commitment_accum));
    A_terms.push((
      ((y_pows * z) - (d.sum() * y_mn_plus_one * z) - (y_pows * (z * z))),
      BpPlusGenerators::g(),
    ));

    AHatComputation {
      y,
      d_descending_y_plus_z,
      y_mn_plus_one,
      z,
      z_pow: ScalarVector(z_pow),
      A_hat: A + multiexp_vartime(&A_terms),
    }
  }

  pub(crate) fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    witness: &AggregateRangeWitness,
  ) -> Option<AggregateRangeProof> {
    // Check for consistency with the witness
    if self.V.len() != witness.0.len() {
      return None;
    }
    for (commitment, witness) in self.V.iter().zip(witness.0.iter()) {
      if witness.calculate() != *commitment {
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
    let V = V.into_iter().map(|V| V * INV_EIGHT()).collect::<Vec<_>>();
    let mut transcript = initial_transcript(V.iter());
    let mut V = V.iter().map(EdwardsPoint::mul_by_cofactor).collect::<Vec<_>>();

    // Pad V
    while V.len() < padded_pow_of_2(V.len()) {
      V.push(EdwardsPoint::identity());
    }

    let generators = generators.reduce(V.len() * N);

    let mut d_js = Vec::with_capacity(V.len());
    let mut a_l = ScalarVector(Vec::with_capacity(V.len() * N));
    for j in 1 ..= V.len() {
      d_js.push(Self::d_j(j, V.len()));
      #[allow(clippy::map_unwrap_or)]
      a_l.0.append(
        &mut u64_decompose(
          *witness.0.get(j - 1).map(|commitment| &commitment.amount).unwrap_or(&0),
        )
        .0,
      );
    }

    let a_r = a_l.clone() - Scalar::ONE;

    let alpha = Scalar::random(&mut *rng);

    let mut A_terms = Vec::with_capacity((generators.len() * 2) + 1);
    for (i, a_l) in a_l.0.iter().enumerate() {
      A_terms.push((*a_l, generators.generator(GeneratorsList::GBold, i)));
    }
    for (i, a_r) in a_r.0.iter().enumerate() {
      A_terms.push((*a_r, generators.generator(GeneratorsList::HBold, i)));
    }
    A_terms.push((alpha, BpPlusGenerators::h()));
    let mut A = multiexp(&A_terms);
    A_terms.zeroize();

    // Multiply by INV_EIGHT per earlier commentary
    A *= INV_EIGHT();

    let AHatComputation { y, d_descending_y_plus_z, y_mn_plus_one, z, z_pow, A_hat } =
      Self::compute_A_hat(PointVector(V), &generators, &mut transcript, A);

    let a_l = a_l - z;
    let a_r = a_r + &d_descending_y_plus_z;
    let mut alpha = alpha;
    for j in 1 ..= witness.0.len() {
      alpha += z_pow[j - 1] * witness.0[j - 1].mask * y_mn_plus_one;
    }

    Some(AggregateRangeProof {
      A,
      wip: WipStatement::new(generators, A_hat, y)
        .prove(rng, transcript, &Zeroizing::new(WipWitness::new(a_l, a_r, alpha).unwrap()))
        .unwrap(),
    })
  }

  pub(crate) fn verify<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BulletproofsPlusBatchVerifier,
    proof: AggregateRangeProof,
  ) -> bool {
    let Self { generators, V } = self;

    let V = V.into_iter().map(|V| V * INV_EIGHT()).collect::<Vec<_>>();
    let mut transcript = initial_transcript(V.iter());
    let V = V.iter().map(EdwardsPoint::mul_by_cofactor).collect::<Vec<_>>();

    let generators = generators.reduce(V.len() * N);

    let AHatComputation { y, A_hat, .. } =
      Self::compute_A_hat(PointVector(V), &generators, &mut transcript, proof.A);
    WipStatement::new(generators, A_hat, y).verify(rng, verifier, transcript, proof.wip)
  }
}
