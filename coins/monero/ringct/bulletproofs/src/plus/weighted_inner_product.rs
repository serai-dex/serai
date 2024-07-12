use std_shims::{vec, vec::Vec};

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use monero_primitives::{INV_EIGHT, keccak256_to_scalar};
use crate::{
  core::{multiexp, multiexp_vartime, challenge_products},
  batch_verifier::BulletproofsPlusBatchVerifier,
  plus::{ScalarVector, PointVector, GeneratorsList, BpPlusGenerators, padded_pow_of_2},
};

// Figure 1 of the Bulletproofs+ paper
#[derive(Clone, Debug)]
pub(crate) struct WipStatement {
  generators: BpPlusGenerators,
  P: EdwardsPoint,
  y: ScalarVector,
}

impl Zeroize for WipStatement {
  fn zeroize(&mut self) {
    self.P.zeroize();
    self.y.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct WipWitness {
  a: ScalarVector,
  b: ScalarVector,
  alpha: Scalar,
}

impl WipWitness {
  pub(crate) fn new(mut a: ScalarVector, mut b: ScalarVector, alpha: Scalar) -> Option<Self> {
    if a.0.is_empty() || (a.len() != b.len()) {
      return None;
    }

    // Pad to the nearest power of 2
    let missing = padded_pow_of_2(a.len()) - a.len();
    a.0.reserve(missing);
    b.0.reserve(missing);
    for _ in 0 .. missing {
      a.0.push(Scalar::ZERO);
      b.0.push(Scalar::ZERO);
    }

    Some(Self { a, b, alpha })
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct WipProof {
  pub(crate) L: Vec<EdwardsPoint>,
  pub(crate) R: Vec<EdwardsPoint>,
  pub(crate) A: EdwardsPoint,
  pub(crate) B: EdwardsPoint,
  pub(crate) r_answer: Scalar,
  pub(crate) s_answer: Scalar,
  pub(crate) delta_answer: Scalar,
}

impl WipStatement {
  pub(crate) fn new(generators: BpPlusGenerators, P: EdwardsPoint, y: Scalar) -> Self {
    debug_assert_eq!(generators.len(), padded_pow_of_2(generators.len()));

    // y ** n
    let mut y_vec = ScalarVector::new(generators.len());
    y_vec[0] = y;
    for i in 1 .. y_vec.len() {
      y_vec[i] = y_vec[i - 1] * y;
    }

    Self { generators, P, y: y_vec }
  }

  fn transcript_L_R(transcript: &mut Scalar, L: EdwardsPoint, R: EdwardsPoint) -> Scalar {
    let e = keccak256_to_scalar(
      [
        transcript.to_bytes().as_ref(),
        L.compress().to_bytes().as_ref(),
        R.compress().to_bytes().as_ref(),
      ]
      .concat(),
    );
    *transcript = e;
    e
  }

  fn transcript_A_B(transcript: &mut Scalar, A: EdwardsPoint, B: EdwardsPoint) -> Scalar {
    let e = keccak256_to_scalar(
      [
        transcript.to_bytes().as_ref(),
        A.compress().to_bytes().as_ref(),
        B.compress().to_bytes().as_ref(),
      ]
      .concat(),
    );
    *transcript = e;
    e
  }

  // Prover's variant of the shared code block to calculate G/H/P when n > 1
  // Returns each permutation of G/H since the prover needs to do operation on each permutation
  // P is dropped as it's unused in the prover's path
  #[allow(clippy::too_many_arguments)]
  fn next_G_H(
    transcript: &mut Scalar,
    mut g_bold1: PointVector,
    mut g_bold2: PointVector,
    mut h_bold1: PointVector,
    mut h_bold2: PointVector,
    L: EdwardsPoint,
    R: EdwardsPoint,
    y_inv_n_hat: Scalar,
  ) -> (Scalar, Scalar, Scalar, Scalar, PointVector, PointVector) {
    debug_assert_eq!(g_bold1.len(), g_bold2.len());
    debug_assert_eq!(h_bold1.len(), h_bold2.len());
    debug_assert_eq!(g_bold1.len(), h_bold1.len());

    let e = Self::transcript_L_R(transcript, L, R);
    let inv_e = e.invert();

    // This vartime is safe as all of these arguments are public
    let mut new_g_bold = Vec::with_capacity(g_bold1.len());
    let e_y_inv = e * y_inv_n_hat;
    for g_bold in g_bold1.0.drain(..).zip(g_bold2.0.drain(..)) {
      new_g_bold.push(multiexp_vartime(&[(inv_e, g_bold.0), (e_y_inv, g_bold.1)]));
    }

    let mut new_h_bold = Vec::with_capacity(h_bold1.len());
    for h_bold in h_bold1.0.drain(..).zip(h_bold2.0.drain(..)) {
      new_h_bold.push(multiexp_vartime(&[(e, h_bold.0), (inv_e, h_bold.1)]));
    }

    let e_square = e * e;
    let inv_e_square = inv_e * inv_e;

    (e, inv_e, e_square, inv_e_square, PointVector(new_g_bold), PointVector(new_h_bold))
  }

  pub(crate) fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    mut transcript: Scalar,
    witness: &WipWitness,
  ) -> Option<WipProof> {
    let WipStatement { generators, P, mut y } = self;
    #[cfg(not(debug_assertions))]
    let _ = P;

    if generators.len() != witness.a.len() {
      return None;
    }
    let (g, h) = (BpPlusGenerators::g(), BpPlusGenerators::h());
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for i in 0 .. generators.len() {
      g_bold.push(generators.generator(GeneratorsList::GBold, i));
      h_bold.push(generators.generator(GeneratorsList::HBold, i));
    }
    let mut g_bold = PointVector(g_bold);
    let mut h_bold = PointVector(h_bold);

    let mut y_inv = {
      let mut i = 1;
      let mut to_invert = vec![];
      while i < g_bold.len() {
        to_invert.push(y[i - 1]);
        i *= 2;
      }
      Scalar::batch_invert(&mut to_invert);
      to_invert
    };

    // Check P has the expected relationship
    #[cfg(debug_assertions)]
    {
      let mut P_terms = witness
        .a
        .0
        .iter()
        .copied()
        .zip(g_bold.0.iter().copied())
        .chain(witness.b.0.iter().copied().zip(h_bold.0.iter().copied()))
        .collect::<Vec<_>>();
      P_terms.push((witness.a.clone().weighted_inner_product(&witness.b, &y), g));
      P_terms.push((witness.alpha, h));
      debug_assert_eq!(multiexp(&P_terms), P);
      P_terms.zeroize();
    }

    let mut a = witness.a.clone();
    let mut b = witness.b.clone();
    let mut alpha = witness.alpha;

    // From here on, g_bold.len() is used as n
    debug_assert_eq!(g_bold.len(), a.len());

    let mut L_vec = vec![];
    let mut R_vec = vec![];

    // else n > 1 case from figure 1
    while g_bold.len() > 1 {
      let (a1, a2) = a.clone().split();
      let (b1, b2) = b.clone().split();
      let (g_bold1, g_bold2) = g_bold.split();
      let (h_bold1, h_bold2) = h_bold.split();

      let n_hat = g_bold1.len();
      debug_assert_eq!(a1.len(), n_hat);
      debug_assert_eq!(a2.len(), n_hat);
      debug_assert_eq!(b1.len(), n_hat);
      debug_assert_eq!(b2.len(), n_hat);
      debug_assert_eq!(g_bold1.len(), n_hat);
      debug_assert_eq!(g_bold2.len(), n_hat);
      debug_assert_eq!(h_bold1.len(), n_hat);
      debug_assert_eq!(h_bold2.len(), n_hat);

      let y_n_hat = y[n_hat - 1];
      y.0.truncate(n_hat);

      let d_l = Scalar::random(&mut *rng);
      let d_r = Scalar::random(&mut *rng);

      let c_l = a1.clone().weighted_inner_product(&b2, &y);
      let c_r = (a2.clone() * y_n_hat).weighted_inner_product(&b1, &y);

      let y_inv_n_hat = y_inv.pop().unwrap();

      let mut L_terms = (a1.clone() * y_inv_n_hat)
        .0
        .drain(..)
        .zip(g_bold2.0.iter().copied())
        .chain(b2.0.iter().copied().zip(h_bold1.0.iter().copied()))
        .collect::<Vec<_>>();
      L_terms.push((c_l, g));
      L_terms.push((d_l, h));
      let L = multiexp(&L_terms) * INV_EIGHT();
      L_vec.push(L);
      L_terms.zeroize();

      let mut R_terms = (a2.clone() * y_n_hat)
        .0
        .drain(..)
        .zip(g_bold1.0.iter().copied())
        .chain(b1.0.iter().copied().zip(h_bold2.0.iter().copied()))
        .collect::<Vec<_>>();
      R_terms.push((c_r, g));
      R_terms.push((d_r, h));
      let R = multiexp(&R_terms) * INV_EIGHT();
      R_vec.push(R);
      R_terms.zeroize();

      let (e, inv_e, e_square, inv_e_square);
      (e, inv_e, e_square, inv_e_square, g_bold, h_bold) =
        Self::next_G_H(&mut transcript, g_bold1, g_bold2, h_bold1, h_bold2, L, R, y_inv_n_hat);

      a = (a1 * e) + &(a2 * (y_n_hat * inv_e));
      b = (b1 * inv_e) + &(b2 * e);
      alpha += (d_l * e_square) + (d_r * inv_e_square);

      debug_assert_eq!(g_bold.len(), a.len());
      debug_assert_eq!(g_bold.len(), h_bold.len());
      debug_assert_eq!(g_bold.len(), b.len());
    }

    // n == 1 case from figure 1
    debug_assert_eq!(g_bold.len(), 1);
    debug_assert_eq!(h_bold.len(), 1);

    debug_assert_eq!(a.len(), 1);
    debug_assert_eq!(b.len(), 1);

    let r = Scalar::random(&mut *rng);
    let s = Scalar::random(&mut *rng);
    let delta = Scalar::random(&mut *rng);
    let eta = Scalar::random(&mut *rng);

    let ry = r * y[0];

    let mut A_terms =
      vec![(r, g_bold[0]), (s, h_bold[0]), ((ry * b[0]) + (s * y[0] * a[0]), g), (delta, h)];
    let A = multiexp(&A_terms) * INV_EIGHT();
    A_terms.zeroize();

    let mut B_terms = vec![(ry * s, g), (eta, h)];
    let B = multiexp(&B_terms) * INV_EIGHT();
    B_terms.zeroize();

    let e = Self::transcript_A_B(&mut transcript, A, B);

    let r_answer = r + (a[0] * e);
    let s_answer = s + (b[0] * e);
    let delta_answer = eta + (delta * e) + (alpha * (e * e));

    Some(WipProof { L: L_vec, R: R_vec, A, B, r_answer, s_answer, delta_answer })
  }

  pub(crate) fn verify<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BulletproofsPlusBatchVerifier,
    mut transcript: Scalar,
    mut proof: WipProof,
  ) -> bool {
    let verifier_weight = Scalar::random(rng);

    let WipStatement { generators, P, y } = self;

    // Verify the L/R lengths
    {
      let mut lr_len = 0;
      while (1 << lr_len) < generators.len() {
        lr_len += 1;
      }
      if (proof.L.len() != lr_len) ||
        (proof.R.len() != lr_len) ||
        (generators.len() != (1 << lr_len))
      {
        return false;
      }
    }

    let inv_y = {
      let inv_y = y[0].invert();
      let mut res = Vec::with_capacity(y.len());
      res.push(inv_y);
      while res.len() < y.len() {
        res.push(inv_y * res.last().unwrap());
      }
      res
    };

    let mut e_is = Vec::with_capacity(proof.L.len());
    for (L, R) in proof.L.iter_mut().zip(proof.R.iter_mut()) {
      e_is.push(Self::transcript_L_R(&mut transcript, *L, *R));
      *L = L.mul_by_cofactor();
      *R = R.mul_by_cofactor();
    }

    let e = Self::transcript_A_B(&mut transcript, proof.A, proof.B);
    proof.A = proof.A.mul_by_cofactor();
    proof.B = proof.B.mul_by_cofactor();
    let neg_e_square = verifier_weight * -(e * e);

    verifier.0.other.push((neg_e_square, P));

    let mut challenges = Vec::with_capacity(proof.L.len());
    let product_cache = {
      let mut inv_e_is = e_is.clone();
      Scalar::batch_invert(&mut inv_e_is);

      debug_assert_eq!(e_is.len(), inv_e_is.len());
      debug_assert_eq!(e_is.len(), proof.L.len());
      debug_assert_eq!(e_is.len(), proof.R.len());
      for ((e_i, inv_e_i), (L, R)) in
        e_is.drain(..).zip(inv_e_is.drain(..)).zip(proof.L.iter().zip(proof.R.iter()))
      {
        debug_assert_eq!(e_i.invert(), inv_e_i);

        challenges.push((e_i, inv_e_i));

        let e_i_square = e_i * e_i;
        let inv_e_i_square = inv_e_i * inv_e_i;
        verifier.0.other.push((neg_e_square * e_i_square, *L));
        verifier.0.other.push((neg_e_square * inv_e_i_square, *R));
      }

      challenge_products(&challenges)
    };

    while verifier.0.g_bold.len() < generators.len() {
      verifier.0.g_bold.push(Scalar::ZERO);
    }
    while verifier.0.h_bold.len() < generators.len() {
      verifier.0.h_bold.push(Scalar::ZERO);
    }

    let re = proof.r_answer * e;
    for i in 0 .. generators.len() {
      let mut scalar = product_cache[i] * re;
      if i > 0 {
        scalar *= inv_y[i - 1];
      }
      verifier.0.g_bold[i] += verifier_weight * scalar;
    }

    let se = proof.s_answer * e;
    for i in 0 .. generators.len() {
      verifier.0.h_bold[i] += verifier_weight * (se * product_cache[product_cache.len() - 1 - i]);
    }

    verifier.0.other.push((verifier_weight * -e, proof.A));
    verifier.0.g += verifier_weight * (proof.r_answer * y[0] * proof.s_answer);
    verifier.0.h += verifier_weight * proof.delta_answer;
    verifier.0.other.push((-verifier_weight, proof.B));

    true
  }
}
