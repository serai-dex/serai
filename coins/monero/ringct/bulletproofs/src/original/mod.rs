use std_shims::{vec, vec::Vec, sync::OnceLock};

use rand_core::{RngCore, CryptoRng};
use zeroize::Zeroize;
use subtle::{Choice, ConditionallySelectable};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
  scalar::Scalar,
  edwards::EdwardsPoint,
};

use monero_generators::{H, Generators};
use monero_primitives::{INV_EIGHT, Commitment, keccak256_to_scalar};

use crate::{core::*, ScalarVector, batch_verifier::BulletproofsBatchVerifier};

include!(concat!(env!("OUT_DIR"), "/generators.rs"));

static TWO_N_CELL: OnceLock<ScalarVector> = OnceLock::new();
fn TWO_N() -> &'static ScalarVector {
  TWO_N_CELL.get_or_init(|| ScalarVector::powers(Scalar::from(2u8), COMMITMENT_BITS))
}

static IP12_CELL: OnceLock<Scalar> = OnceLock::new();
fn IP12() -> Scalar {
  *IP12_CELL.get_or_init(|| ScalarVector(vec![Scalar::ONE; COMMITMENT_BITS]).inner_product(TWO_N()))
}

fn MN(outputs: usize) -> (usize, usize, usize) {
  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_COMMITMENTS) && (M < outputs)
  } {
    logM += 1;
  }

  (logM + LOG_COMMITMENT_BITS, M, M * COMMITMENT_BITS)
}

fn bit_decompose(commitments: &[Commitment]) -> (ScalarVector, ScalarVector) {
  let (_, M, MN) = MN(commitments.len());

  let sv = commitments.iter().map(|c| Scalar::from(c.amount)).collect::<Vec<_>>();
  let mut aL = ScalarVector::new(MN);
  let mut aR = ScalarVector::new(MN);

  for j in 0 .. M {
    for i in (0 .. COMMITMENT_BITS).rev() {
      let bit =
        if j < sv.len() { Choice::from((sv[j][i / 8] >> (i % 8)) & 1) } else { Choice::from(0) };
      aL.0[(j * COMMITMENT_BITS) + i] =
        Scalar::conditional_select(&Scalar::ZERO, &Scalar::ONE, bit);
      aR.0[(j * COMMITMENT_BITS) + i] =
        Scalar::conditional_select(&-Scalar::ONE, &Scalar::ZERO, bit);
    }
  }

  (aL, aR)
}

fn hash_commitments<C: IntoIterator<Item = EdwardsPoint>>(
  commitments: C,
) -> (Scalar, Vec<EdwardsPoint>) {
  let V = commitments.into_iter().map(|c| c * INV_EIGHT()).collect::<Vec<_>>();
  (keccak256_to_scalar(V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>()), V)
}

fn alpha_rho<R: RngCore + CryptoRng>(
  rng: &mut R,
  generators: &Generators,
  aL: &ScalarVector,
  aR: &ScalarVector,
) -> (Scalar, EdwardsPoint) {
  fn vector_exponent(generators: &Generators, a: &ScalarVector, b: &ScalarVector) -> EdwardsPoint {
    debug_assert_eq!(a.len(), b.len());
    (a * &generators.G[.. a.len()]) + (b * &generators.H[.. b.len()])
  }

  let ar = Scalar::random(rng);
  (ar, (vector_exponent(generators, aL, aR) + (ED25519_BASEPOINT_TABLE * &ar)) * INV_EIGHT())
}

fn LR_statements(
  a: &ScalarVector,
  G_i: &[EdwardsPoint],
  b: &ScalarVector,
  H_i: &[EdwardsPoint],
  cL: Scalar,
  U: EdwardsPoint,
) -> Vec<(Scalar, EdwardsPoint)> {
  let mut res = a
    .0
    .iter()
    .copied()
    .zip(G_i.iter().copied())
    .chain(b.0.iter().copied().zip(H_i.iter().copied()))
    .collect::<Vec<_>>();
  res.push((cL, U));
  res
}

fn hash_cache(cache: &mut Scalar, mash: &[[u8; 32]]) -> Scalar {
  let slice =
    &[cache.to_bytes().as_ref(), mash.iter().copied().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  *cache = keccak256_to_scalar(slice);
  *cache
}

fn hadamard_fold(
  l: &[EdwardsPoint],
  r: &[EdwardsPoint],
  a: Scalar,
  b: Scalar,
) -> Vec<EdwardsPoint> {
  let mut res = Vec::with_capacity(l.len() / 2);
  for i in 0 .. l.len() {
    res.push(multiexp(&[(a, l[i]), (b, r[i])]));
  }
  res
}

/// Internal structure representing a Bulletproof, as defined by Monero..
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OriginalStruct {
  pub(crate) A: EdwardsPoint,
  pub(crate) S: EdwardsPoint,
  pub(crate) T1: EdwardsPoint,
  pub(crate) T2: EdwardsPoint,
  pub(crate) tau_x: Scalar,
  pub(crate) mu: Scalar,
  pub(crate) L: Vec<EdwardsPoint>,
  pub(crate) R: Vec<EdwardsPoint>,
  pub(crate) a: Scalar,
  pub(crate) b: Scalar,
  pub(crate) t: Scalar,
}

impl OriginalStruct {
  pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: &[Commitment],
  ) -> OriginalStruct {
    let (logMN, M, MN) = MN(commitments.len());

    let (aL, aR) = bit_decompose(commitments);
    let commitments_points = commitments.iter().map(Commitment::calculate).collect::<Vec<_>>();
    let (mut cache, _) = hash_commitments(commitments_points.clone());

    let (sL, sR) =
      ScalarVector((0 .. (MN * 2)).map(|_| Scalar::random(&mut *rng)).collect::<Vec<_>>()).split();

    let generators = GENERATORS();
    let (mut alpha, A) = alpha_rho(&mut *rng, generators, &aL, &aR);
    let (mut rho, S) = alpha_rho(&mut *rng, generators, &sL, &sR);

    let y = hash_cache(&mut cache, &[A.compress().to_bytes(), S.compress().to_bytes()]);
    let mut cache = keccak256_to_scalar(y.to_bytes());
    let z = cache;

    let l0 = aL - z;
    let l1 = sL;

    let mut zero_twos = Vec::with_capacity(MN);
    let zpow = ScalarVector::powers(z, M + 2);
    for j in 0 .. M {
      for i in 0 .. COMMITMENT_BITS {
        zero_twos.push(zpow[j + 2] * TWO_N()[i]);
      }
    }

    let yMN = ScalarVector::powers(y, MN);
    let r0 = ((aR + z) * &yMN) + &ScalarVector(zero_twos);
    let r1 = yMN * &sR;

    let (T1, T2, x, mut tau_x) = {
      let t1 = l0.clone().inner_product(&r1) + r0.clone().inner_product(&l1);
      let t2 = l1.clone().inner_product(&r1);

      let mut tau1 = Scalar::random(&mut *rng);
      let mut tau2 = Scalar::random(&mut *rng);

      let T1 = multiexp(&[(t1, H()), (tau1, ED25519_BASEPOINT_POINT)]) * INV_EIGHT();
      let T2 = multiexp(&[(t2, H()), (tau2, ED25519_BASEPOINT_POINT)]) * INV_EIGHT();

      let x =
        hash_cache(&mut cache, &[z.to_bytes(), T1.compress().to_bytes(), T2.compress().to_bytes()]);

      let tau_x = (tau2 * (x * x)) + (tau1 * x);

      tau1.zeroize();
      tau2.zeroize();
      (T1, T2, x, tau_x)
    };

    let mu = (x * rho) + alpha;
    alpha.zeroize();
    rho.zeroize();

    for (i, gamma) in commitments.iter().map(|c| c.mask).enumerate() {
      tau_x += zpow[i + 2] * gamma;
    }

    let l = l0 + &(l1 * x);
    let r = r0 + &(r1 * x);

    let t = l.clone().inner_product(&r);

    let x_ip =
      hash_cache(&mut cache, &[x.to_bytes(), tau_x.to_bytes(), mu.to_bytes(), t.to_bytes()]);

    let mut a = l;
    let mut b = r;

    let yinv = y.invert();
    let yinvpow = ScalarVector::powers(yinv, MN);

    let mut G_proof = generators.G[.. a.len()].to_vec();
    let mut H_proof = generators.H[.. a.len()].to_vec();
    H_proof.iter_mut().zip(yinvpow.0.iter()).for_each(|(this_H, yinvpow)| *this_H *= yinvpow);
    let U = H() * x_ip;

    let mut L = Vec::with_capacity(logMN);
    let mut R = Vec::with_capacity(logMN);

    while a.len() != 1 {
      let (aL, aR) = a.split();
      let (bL, bR) = b.split();

      let cL = aL.clone().inner_product(&bR);
      let cR = aR.clone().inner_product(&bL);

      let (G_L, G_R) = G_proof.split_at(aL.len());
      let (H_L, H_R) = H_proof.split_at(aL.len());

      let L_i = multiexp(&LR_statements(&aL, G_R, &bR, H_L, cL, U)) * INV_EIGHT();
      let R_i = multiexp(&LR_statements(&aR, G_L, &bL, H_R, cR, U)) * INV_EIGHT();
      L.push(L_i);
      R.push(R_i);

      let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
      let w_inv = w.invert();

      a = (aL * w) + &(aR * w_inv);
      b = (bL * w_inv) + &(bR * w);

      if a.len() != 1 {
        G_proof = hadamard_fold(G_L, G_R, w_inv, w);
        H_proof = hadamard_fold(H_L, H_R, w, w_inv);
      }
    }

    let res = OriginalStruct { A, S, T1, T2, tau_x, mu, L, R, a: a[0], b: b[0], t };

    #[cfg(debug_assertions)]
    {
      let mut verifier = BulletproofsBatchVerifier::default();
      debug_assert!(res.verify(rng, &mut verifier, &commitments_points));
      debug_assert!(verifier.verify());
    }

    res
  }

  #[must_use]
  pub(crate) fn verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BulletproofsBatchVerifier,
    commitments: &[EdwardsPoint],
  ) -> bool {
    // Verify commitments are valid
    if commitments.is_empty() || (commitments.len() > MAX_COMMITMENTS) {
      return false;
    }

    // Verify L and R are properly sized
    if self.L.len() != self.R.len() {
      return false;
    }

    let (logMN, M, MN) = MN(commitments.len());
    if self.L.len() != logMN {
      return false;
    }

    // Rebuild all challenges
    let (mut cache, commitments) = hash_commitments(commitments.iter().copied());
    let y = hash_cache(&mut cache, &[self.A.compress().to_bytes(), self.S.compress().to_bytes()]);

    let z = keccak256_to_scalar(y.to_bytes());
    cache = z;

    let x = hash_cache(
      &mut cache,
      &[z.to_bytes(), self.T1.compress().to_bytes(), self.T2.compress().to_bytes()],
    );

    let x_ip = hash_cache(
      &mut cache,
      &[x.to_bytes(), self.tau_x.to_bytes(), self.mu.to_bytes(), self.t.to_bytes()],
    );

    let mut w_and_w_inv = Vec::with_capacity(logMN);
    for (L, R) in self.L.iter().zip(&self.R) {
      let w = hash_cache(&mut cache, &[L.compress().to_bytes(), R.compress().to_bytes()]);
      let w_inv = w.invert();
      w_and_w_inv.push((w, w_inv));
    }

    // Convert the proof from * INV_EIGHT to its actual form
    let normalize = |point: &EdwardsPoint| point.mul_by_cofactor();

    let L = self.L.iter().map(normalize).collect::<Vec<_>>();
    let R = self.R.iter().map(normalize).collect::<Vec<_>>();
    let T1 = normalize(&self.T1);
    let T2 = normalize(&self.T2);
    let A = normalize(&self.A);
    let S = normalize(&self.S);

    let commitments = commitments.iter().map(EdwardsPoint::mul_by_cofactor).collect::<Vec<_>>();

    // Verify it
    let zpow = ScalarVector::powers(z, M + 3);

    // First multiexp
    {
      let verifier_weight = Scalar::random(rng);

      let ip1y = ScalarVector::powers(y, M * COMMITMENT_BITS).sum();
      let mut k = -(zpow[2] * ip1y);
      for j in 1 ..= M {
        k -= zpow[j + 2] * IP12();
      }
      let y1 = self.t - ((z * ip1y) + k);
      verifier.0.h -= verifier_weight * y1;

      verifier.0.g -= verifier_weight * self.tau_x;

      for (j, commitment) in commitments.iter().enumerate() {
        verifier.0.other.push((verifier_weight * zpow[j + 2], *commitment));
      }

      verifier.0.other.push((verifier_weight * x, T1));
      verifier.0.other.push((verifier_weight * (x * x), T2));
    }

    // Second multiexp
    {
      let verifier_weight = Scalar::random(rng);
      let z3 = (self.t - (self.a * self.b)) * x_ip;
      verifier.0.h += verifier_weight * z3;
      verifier.0.g -= verifier_weight * self.mu;

      verifier.0.other.push((verifier_weight, A));
      verifier.0.other.push((verifier_weight * x, S));

      {
        let ypow = ScalarVector::powers(y, MN);
        let yinv = y.invert();
        let yinvpow = ScalarVector::powers(yinv, MN);

        let w_cache = challenge_products(&w_and_w_inv);

        while verifier.0.g_bold.len() < MN {
          verifier.0.g_bold.push(Scalar::ZERO);
        }
        while verifier.0.h_bold.len() < MN {
          verifier.0.h_bold.push(Scalar::ZERO);
        }

        for i in 0 .. MN {
          let g = (self.a * w_cache[i]) + z;
          verifier.0.g_bold[i] -= verifier_weight * g;

          let mut h = self.b * yinvpow[i] * w_cache[(!i) & (MN - 1)];
          h -= ((zpow[(i / COMMITMENT_BITS) + 2] * TWO_N()[i % COMMITMENT_BITS]) + (z * ypow[i])) *
            yinvpow[i];
          verifier.0.h_bold[i] -= verifier_weight * h;
        }
      }

      for i in 0 .. logMN {
        verifier.0.other.push((verifier_weight * (w_and_w_inv[i].0 * w_and_w_inv[i].0), L[i]));
        verifier.0.other.push((verifier_weight * (w_and_w_inv[i].1 * w_and_w_inv[i].1), R[i]));
      }
    }

    true
  }
}
