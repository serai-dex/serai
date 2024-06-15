use std_shims::{vec, vec::Vec, sync::OnceLock};

use rand_core::{RngCore, CryptoRng};
use subtle::{Choice, ConditionallySelectable};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::{MultiscalarMul, VartimeMultiscalarMul},
  scalar::Scalar,
  edwards::EdwardsPoint,
};

pub(crate) use monero_generators::Generators;
use monero_primitives::{INV_EIGHT, Commitment, keccak256_to_scalar};

pub(crate) use crate::scalar_vector::*;

// Components common between variants
// TODO: Move to generators? primitives?
pub(crate) const MAX_M: usize = 16;
pub(crate) const LOG_N: usize = 6; // 2 << 6 == N
pub(crate) const N: usize = 64;

pub(crate) fn multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  let mut buf_scalars = Vec::with_capacity(pairs.len());
  let mut buf_points = Vec::with_capacity(pairs.len());
  for (scalar, point) in pairs {
    buf_scalars.push(scalar);
    buf_points.push(point);
  }
  EdwardsPoint::multiscalar_mul(buf_scalars, buf_points)
}

pub(crate) fn multiexp_vartime(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  let mut buf_scalars = Vec::with_capacity(pairs.len());
  let mut buf_points = Vec::with_capacity(pairs.len());
  for (scalar, point) in pairs {
    buf_scalars.push(scalar);
    buf_points.push(point);
  }
  EdwardsPoint::vartime_multiscalar_mul(buf_scalars, buf_points)
}

pub(crate) fn vector_exponent(
  generators: &Generators,
  a: &ScalarVector,
  b: &ScalarVector,
) -> EdwardsPoint {
  debug_assert_eq!(a.len(), b.len());
  (a * &generators.G[.. a.len()]) + (b * &generators.H[.. b.len()])
}

pub(crate) fn hash_cache(cache: &mut Scalar, mash: &[[u8; 32]]) -> Scalar {
  let slice =
    &[cache.to_bytes().as_ref(), mash.iter().copied().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  *cache = keccak256_to_scalar(slice);
  *cache
}

pub(crate) fn MN(outputs: usize) -> (usize, usize, usize) {
  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_M) && (M < outputs)
  } {
    logM += 1;
  }

  (logM + LOG_N, M, M * N)
}

pub(crate) fn bit_decompose(commitments: &[Commitment]) -> (ScalarVector, ScalarVector) {
  let (_, M, MN) = MN(commitments.len());

  let sv = commitments.iter().map(|c| Scalar::from(c.amount)).collect::<Vec<_>>();
  let mut aL = ScalarVector::new(MN);
  let mut aR = ScalarVector::new(MN);

  for j in 0 .. M {
    for i in (0 .. N).rev() {
      let bit =
        if j < sv.len() { Choice::from((sv[j][i / 8] >> (i % 8)) & 1) } else { Choice::from(0) };
      aL.0[(j * N) + i] = Scalar::conditional_select(&Scalar::ZERO, &Scalar::ONE, bit);
      aR.0[(j * N) + i] = Scalar::conditional_select(&-Scalar::ONE, &Scalar::ZERO, bit);
    }
  }

  (aL, aR)
}

pub(crate) fn hash_commitments<C: IntoIterator<Item = EdwardsPoint>>(
  commitments: C,
) -> (Scalar, Vec<EdwardsPoint>) {
  let V = commitments.into_iter().map(|c| c * INV_EIGHT()).collect::<Vec<_>>();
  (keccak256_to_scalar(V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>()), V)
}

pub(crate) fn alpha_rho<R: RngCore + CryptoRng>(
  rng: &mut R,
  generators: &Generators,
  aL: &ScalarVector,
  aR: &ScalarVector,
) -> (Scalar, EdwardsPoint) {
  let ar = Scalar::random(rng);
  (ar, (vector_exponent(generators, aL, aR) + (ED25519_BASEPOINT_TABLE * &ar)) * INV_EIGHT())
}

pub(crate) fn LR_statements(
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

static TWO_N_CELL: OnceLock<ScalarVector> = OnceLock::new();
pub(crate) fn TWO_N() -> &'static ScalarVector {
  TWO_N_CELL.get_or_init(|| ScalarVector::powers(Scalar::from(2u8), N))
}

pub(crate) fn challenge_products(w: &[Scalar], winv: &[Scalar]) -> Vec<Scalar> {
  let mut products = vec![Scalar::ZERO; 1 << w.len()];
  products[0] = winv[0];
  products[1] = w[0];
  for j in 1 .. w.len() {
    let mut slots = (1 << (j + 1)) - 1;
    while slots > 0 {
      products[slots] = products[slots / 2] * w[j];
      products[slots - 1] = products[slots / 2] * winv[j];
      slots = slots.saturating_sub(2);
    }
  }

  // Sanity check as if the above failed to populate, it'd be critical
  for w in &products {
    debug_assert!(*w != Scalar::ZERO);
  }

  products
}
