// Required to be for this entire file, which isn't an issue, as it wouldn't bind to the static
#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use subtle::{Choice, ConditionallySelectable};

use curve25519_dalek::edwards::EdwardsPoint as DalekPoint;

use group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};

use multiexp::multiexp as multiexp_const;

pub(crate) use monero_generators::Generators;

use crate::{H as DALEK_H, Commitment, hash_to_scalar as dalek_hash};
pub(crate) use crate::ringct::bulletproofs::scalar_vector::*;

// Bring things into ff/group
lazy_static! {
  pub(crate) static ref INV_EIGHT: Scalar = Scalar::from(8u8).invert().unwrap();
  pub(crate) static ref H: EdwardsPoint = EdwardsPoint(*DALEK_H);
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar(dalek_hash(data))
}

// Components common between variants
pub(crate) const MAX_M: usize = 16;
pub(crate) const LOG_N: usize = 6; // 2 << 6 == N
pub(crate) const N: usize = 64;

pub(crate) fn prove_multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  multiexp_const(pairs) * *INV_EIGHT
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
    &[cache.to_bytes().as_ref(), mash.iter().cloned().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  *cache = hash_to_scalar(slice);
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
      let mut bit = Choice::from(0);
      if j < sv.len() {
        bit = Choice::from((sv[j][i / 8] >> (i % 8)) & 1);
      }
      aL.0[(j * N) + i] = Scalar::conditional_select(&Scalar::zero(), &Scalar::one(), bit);
      aR.0[(j * N) + i] = Scalar::conditional_select(&-Scalar::one(), &Scalar::zero(), bit);
    }
  }

  (aL, aR)
}

pub(crate) fn hash_commitments<C: IntoIterator<Item = DalekPoint>>(
  commitments: C,
) -> (Scalar, Vec<EdwardsPoint>) {
  let V = commitments.into_iter().map(|c| EdwardsPoint(c) * *INV_EIGHT).collect::<Vec<_>>();
  (hash_to_scalar(&V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>()), V)
}

pub(crate) fn alpha_rho<R: RngCore + CryptoRng>(
  rng: &mut R,
  generators: &Generators,
  aL: &ScalarVector,
  aR: &ScalarVector,
) -> (Scalar, EdwardsPoint) {
  let ar = Scalar::random(rng);
  (ar, (vector_exponent(generators, aL, aR) + (EdwardsPoint::generator() * ar)) * *INV_EIGHT)
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
    .cloned()
    .zip(G_i.iter().cloned())
    .chain(b.0.iter().cloned().zip(H_i.iter().cloned()))
    .collect::<Vec<_>>();
  res.push((cL, U));
  res
}

lazy_static! {
  pub(crate) static ref TWO_N: ScalarVector = ScalarVector::powers(Scalar::from(2u8), N);
}

pub(crate) fn challenge_products(w: &[Scalar], winv: &[Scalar]) -> Vec<Scalar> {
  let mut products = vec![Scalar::zero(); 1 << w.len()];
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
    debug_assert!(!bool::from(w.is_zero()));
  }

  products
}
