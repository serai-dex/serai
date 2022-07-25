// Required to be for this entire file, which isn't an issue, as it wouldn't bind to the static
#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};

use multiexp::multiexp;

use crate::{
  H as DALEK_H, Commitment, random_scalar as dalek_random, hash, hash_to_scalar as dalek_hash,
  ringct::{hash_to_point::raw_hash_to_point, bulletproofs::{scalar_vector::*, Bulletproofs}},
  serialize::write_varint
};

pub(crate) const MAX_M: usize = 16;
pub(crate) const MAX_N: usize = 64;
const MAX_MN: usize = MAX_M * MAX_N;

// Wrap random_scalar and hash_to_scalar into dalek_ff_group
fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
  Scalar(dalek_random(rng))
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar(dalek_hash(data))
}

fn generator(i: usize) -> EdwardsPoint {
  let mut transcript = (*H).compress().to_bytes().to_vec();
  transcript.extend(b"bulletproof");
  write_varint(&i.try_into().unwrap(), &mut transcript).unwrap();
  EdwardsPoint(raw_hash_to_point(hash(&transcript)))
}

lazy_static! {
  static ref INV_EIGHT: Scalar = Scalar::from(8u8).invert().unwrap();
  static ref H: EdwardsPoint = EdwardsPoint(*DALEK_H);

  pub(crate) static ref ONE_N: ScalarVector = ScalarVector(vec![Scalar::one(); MAX_N]);
  pub(crate) static ref TWO_N: ScalarVector = ScalarVector(vec![Scalar::from(2u8); MAX_N]);
  pub(crate) static ref IP12: Scalar = inner_product(&*ONE_N, &*TWO_N);

  static ref H_i: Vec<EdwardsPoint> = (0 .. MAX_MN).map(|g| generator(g * 2)).collect();
  static ref G_i: Vec<EdwardsPoint> = (0 .. MAX_MN).map(|g| generator((g * 2) + 1)).collect();
}

pub(crate) fn vector_exponent(a: &ScalarVector, b: &ScalarVector) -> EdwardsPoint {
  assert_eq!(a.len(), b.len());
  (a * &G_i[.. a.len()]) + (b * &H_i[.. b.len()])
}

fn hash_cache(cache: &mut Scalar, mash: &[[u8; 32]]) -> Scalar {
  let slice = &[cache.to_bytes().as_ref(), mash.iter().cloned().flatten().collect::<Vec<_>>().as_ref()].concat();
  *cache = hash_to_scalar(slice);
  *cache
}

pub(crate) fn prove<R: RngCore + CryptoRng>(rng: &mut R, commitments: &[Commitment]) -> Bulletproofs {
  let sv = ScalarVector(commitments.iter().cloned().map(|c| Scalar::from(c.amount)).collect());
  let gamma = ScalarVector(commitments.iter().cloned().map(|c| Scalar(c.mask)).collect());

  let logN = 6;
  let N = 1 << logN;

  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_M) && (M < sv.len())
  } {
    logM += 1;
  }

  let logMN = logM + logN;
  let MN = M * N;

  let mut aL = ScalarVector(vec![Scalar::zero(); MN]);
  let mut aR = ScalarVector(vec![Scalar::zero(); MN]);

  for j in 0 .. M {
    for i in (0 .. N).rev() {
      if (j < sv.len()) && ((sv[j][i / 8] & (1u8 << (i % 8))) != 0) {
        aL.0[(j * N) + i] = Scalar::one();
      } else {
        aR.0[(j * N) + i] = -Scalar::one();
      }
    }
  }

  {
    for j in 0 .. M {
      let mut test_aL = 0;
      let mut test_aR = 0;
      for i in 0 .. N {
        if aL[(j * N) + i] == Scalar::one() {
          test_aL += 1 << i;
        }
        if aR[(j * N) + i] == Scalar::zero() {
          test_aR += 1 << i;
        }
      }
      let mut test = 0;
      if j < sv.len() {
        for n in 0 .. 8 {
          test |= u64::from(sv[j][n]) << (8 * n);
        }
      }
      debug_assert_eq!(test_aL, test);
      debug_assert_eq!(test_aR, test);
    }
  }

  // Commitments * INV_EIGHT
  let V = commitments.iter().map(|c| EdwardsPoint(c.calculate()) * *INV_EIGHT).collect::<Vec<_>>();
  let mut cache = hash_to_scalar(&V.iter().map(|V| V.compress().to_bytes()).flatten().collect::<Vec<_>>());

  let alpha = random_scalar(&mut *rng);
  let A = (vector_exponent(&aL, &aR) + (EdwardsPoint::generator() * alpha)) * *INV_EIGHT;

  let sL = ScalarVector((0 .. MN).map(|_| random_scalar(&mut *rng)).collect::<Vec<_>>());
  let sR = ScalarVector((0 .. MN).map(|_| random_scalar(&mut *rng)).collect::<Vec<_>>());
  let rho = random_scalar(&mut *rng);
  let S = (vector_exponent(&sL, &sR) + (EdwardsPoint::generator() * rho)) * *INV_EIGHT;

  let y = hash_cache(&mut cache, &[A.compress().to_bytes(), S.compress().to_bytes()]);
  assert!(y != Scalar::zero());
  let mut cache = hash_to_scalar(&y.to_bytes());
  let z = cache;
  assert!(z != Scalar::zero());

  let l0 = &aL - z;
  let l1 = sL;

  let mut zero_twos = Vec::with_capacity(MN);
  let zpow = vector_powers(z, M + 2);
  for j in 0 .. M {
    for i in 0 .. N {
      zero_twos.push(zpow[j + 2] * TWO_N[i]);
    }
  }

  let yMN = vector_powers(y, MN);
  let r0 = (&(aR + z) * &yMN) + ScalarVector(zero_twos);
  let r1 = yMN * sR;

  let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
  let t2 = inner_product(&l1, &r1);

  let tau1 = random_scalar(&mut *rng);
  let tau2 = random_scalar(&mut *rng);

  let T1 = multiexp(&[(t1, *H), (tau1, EdwardsPoint::generator())]) * *INV_EIGHT;
  let T2 = multiexp(&[(t2, *H), (tau2, EdwardsPoint::generator())]) * *INV_EIGHT;

  let x = hash_cache(&mut cache, &[z.to_bytes(), T1.compress().to_bytes(), T2.compress().to_bytes()]);
  assert!(x != Scalar::zero());

  let mut taux = (tau2 * (x * x)) + (tau1 * x);
  for i in 1 ..= sv.len() {
    taux += zpow[i + 1] * gamma[i - 1];
  }
  let mu = (x * rho) + alpha;

  let l = &l0 + &(l1 * x);
  let r = &r0 + &(r1 * x);

  let t = inner_product(&l, &r);

  {
    let t0 = inner_product(&l0, &r0);
    assert_eq!((t2 * x * x) + ((t1 * x) + t0), t);
  }

  let x_ip = hash_cache(&mut cache, &[x.to_bytes(), taux.to_bytes(), mu.to_bytes(), t.to_bytes()]);
  assert!(x_ip != Scalar::zero());

  let mut n_prime = MN;
  let mut a_prime = l;
  let mut b_prime = r;
  assert_eq!(a_prime.len(), n_prime);
  assert_eq!(b_prime.len(), n_prime);

  let yinv = y.invert().unwrap();
  let yinvpow = vector_powers(yinv, MN);

  let mut G_prime = G_i[.. n_prime].to_vec();
  let mut H_prime = H_i[.. n_prime].iter().enumerate().map(|(i, this_H)| *this_H * yinvpow[i]).collect::<Vec<_>>();
  let U = *H * x_ip;

  let mut L = Vec::with_capacity(logMN);
  let mut R = Vec::with_capacity(logMN);

  while n_prime > 1 {
    n_prime /= 2;

    let aL = a_prime.slice(.. n_prime);
    let aR = a_prime.slice(n_prime ..);

    let bL = b_prime.slice(.. n_prime);
    let bR = b_prime.slice(n_prime ..);

    let cL = inner_product(&aL, &bR);
    let cR = inner_product(&aR, &bL);

    let G_L = G_prime[.. n_prime].to_vec();
    let G_R = G_prime[n_prime ..].to_vec();

    let H_L = H_prime[.. n_prime].to_vec();
    let H_R = H_prime[n_prime ..].to_vec();

    let mut L_i_s = aL.0.iter().cloned().zip(G_R.iter().cloned()).chain(
      bR.0.iter().cloned().zip(H_L.iter().cloned())
    ).collect::<Vec<_>>();
    L_i_s.push((cL, U));
    let L_i = multiexp(&L_i_s) * *INV_EIGHT;

    let mut R_i_s = aR.0.iter().cloned().zip(G_L.iter().cloned()).chain(
      bL.0.iter().cloned().zip(H_R.iter().cloned())
    ).collect::<Vec<_>>();
    R_i_s.push((cR, U));
    let R_i = multiexp(&R_i_s) * *INV_EIGHT;

    L.push(L_i);
    R.push(R_i);

    let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
    assert!(w != Scalar::zero());

    let winv = w.invert().unwrap();
    if n_prime > 1 {
      hadamard_fold(&mut G_prime, winv, w);
      hadamard_fold(&mut H_prime, w, winv);
    }

    a_prime = (aL * w) + (aR * winv);
    b_prime = (bL * winv) + (bR * w);
  }
  assert_eq!(L.len(), logMN);
  assert_eq!(R.len(), logMN);
  assert_eq!(a_prime.len(), 1);
  assert_eq!(b_prime.len(), 1);

  Bulletproofs {
    A: *A,
    S: *S,
    T1: *T1,
    T2: *T2,
    taux: *taux,
    mu: *mu,
    L: L.drain(..).map(|L| *L).collect(),
    R: R.drain(..).map(|R| *R).collect(),
    a: *a_prime[0],
    b: *b_prime[0],
    t: *t
  }
}
