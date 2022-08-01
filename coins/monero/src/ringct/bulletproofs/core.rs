// Required to be for this entire file, which isn't an issue, as it wouldn't bind to the static
#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::EdwardsPoint as DalekPoint;

use group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};

use multiexp::multiexp as multiexp_const;

use crate::{
  H as DALEK_H, Commitment, hash, hash_to_scalar as dalek_hash,
  ringct::hash_to_point::raw_hash_to_point, serialize::write_varint,
};
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
pub(crate) const N: usize = 64;
pub(crate) const MAX_MN: usize = MAX_M * N;

pub(crate) struct Generators {
  pub(crate) G: Vec<EdwardsPoint>,
  pub(crate) H: Vec<EdwardsPoint>,
}

pub(crate) fn generators_core(prefix: &'static [u8]) -> Generators {
  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    let i = 2 * i;

    let mut even = (*H).compress().to_bytes().to_vec();
    even.extend(prefix);
    let mut odd = even.clone();

    write_varint(&i.try_into().unwrap(), &mut even).unwrap();
    write_varint(&(i + 1).try_into().unwrap(), &mut odd).unwrap();
    res.H.push(EdwardsPoint(raw_hash_to_point(hash(&even))));
    res.G.push(EdwardsPoint(raw_hash_to_point(hash(&odd))));
  }
  res
}

pub(crate) fn prove_multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  multiexp_const(pairs) * *INV_EIGHT
}

// TODO: Have this take in other, multiplied by G, and do a single multiexp
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
  let logN = 6;
  debug_assert_eq!(N, 1 << logN);

  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_M) && (M < outputs)
  } {
    logM += 1;
  }

  (logM + logN, M, M * N)
}

pub(crate) fn bit_decompose(commitments: &[Commitment]) -> (ScalarVector, ScalarVector) {
  let (_, M, MN) = MN(commitments.len());

  let sv = commitments.iter().map(|c| Scalar::from(c.amount)).collect::<Vec<_>>();
  let mut aL = ScalarVector::new(MN);
  let mut aR = ScalarVector::new(MN);

  for j in 0 .. M {
    for i in (0 .. N).rev() {
      if (j < sv.len()) && ((sv[j][i / 8] & (1u8 << (i % 8))) != 0) {
        aL.0[(j * N) + i] = Scalar::one();
      } else {
        aR.0[(j * N) + i] = -Scalar::one();
      }
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
