use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use curve25519_dalek::{scalar::Scalar as DalekScalar, edwards::EdwardsPoint as DalekPoint};

use group::ff::Field;
use dalek_ff_group::{ED25519_BASEPOINT_POINT as G, Scalar, EdwardsPoint};

use multiexp::BatchVerifier;

use crate::{
  Commitment, hash,
  ringct::{hash_to_point::raw_hash_to_point, bulletproofs::core::*},
};

include!("../../../.generators/generators_plus.rs");

lazy_static! {
  static ref TRANSCRIPT: [u8; 32] =
    EdwardsPoint(raw_hash_to_point(hash(b"bulletproof_plus_transcript"))).compress().to_bytes();
}

// TRANSCRIPT isn't a Scalar, so we need this alternative for the first hash
fn hash_plus<C: IntoIterator<Item = DalekPoint>>(commitments: C) -> (Scalar, Vec<EdwardsPoint>) {
  let (cache, commitments) = hash_commitments(commitments);
  (hash_to_scalar(&[&*TRANSCRIPT as &[u8], &cache.to_bytes()].concat()), commitments)
}

// d[j*N+i] = z**(2*(j+1)) * 2**i
fn d(z: Scalar, M: usize, MN: usize) -> (ScalarVector, ScalarVector) {
  let zpow = ScalarVector::even_powers(z, 2 * M);
  let mut d = vec![Scalar::zero(); MN];
  for j in 0 .. M {
    for i in 0 .. N {
      d[(j * N) + i] = zpow[j] * TWO_N[i];
    }
  }
  (zpow, ScalarVector(d))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlusStruct {
  pub(crate) A: DalekPoint,
  pub(crate) A1: DalekPoint,
  pub(crate) B: DalekPoint,
  pub(crate) r1: DalekScalar,
  pub(crate) s1: DalekScalar,
  pub(crate) d1: DalekScalar,
  pub(crate) L: Vec<DalekPoint>,
  pub(crate) R: Vec<DalekPoint>,
}

impl PlusStruct {
  pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: &[Commitment],
  ) -> PlusStruct {
    let (logMN, M, MN) = MN(commitments.len());

    let (aL, aR) = bit_decompose(commitments);
    let (mut cache, _) = hash_plus(commitments.iter().map(Commitment::calculate));
    let (mut alpha1, A) = alpha_rho(&mut *rng, &GENERATORS, &aL, &aR);

    let y = hash_cache(&mut cache, &[A.compress().to_bytes()]);
    let mut cache = hash_to_scalar(&y.to_bytes());
    let z = cache;

    let (zpow, d) = d(z, M, MN);

    let aL1 = aL - z;

    let ypow = ScalarVector::powers(y, MN + 2);
    let mut y_for_d = ScalarVector(ypow.0[1 ..= MN].to_vec());
    y_for_d.0.reverse();
    let aR1 = (aR + z) + (y_for_d * d);

    for (j, gamma) in commitments.iter().map(|c| Scalar(c.mask)).enumerate() {
      alpha1 += zpow[j] * ypow[MN + 1] * gamma;
    }

    let mut a = aL1;
    let mut b = aR1;

    let yinv = y.invert().unwrap();
    let yinvpow = ScalarVector::powers(yinv, MN);

    let mut G_proof = GENERATORS.G[.. a.len()].to_vec();
    let mut H_proof = GENERATORS.H[.. a.len()].to_vec();

    let mut L = Vec::with_capacity(logMN);
    let mut R = Vec::with_capacity(logMN);

    while a.len() != 1 {
      let (aL, aR) = a.split();
      let (bL, bR) = b.split();

      let cL = weighted_inner_product(&aL, &bR, y);
      let cR = weighted_inner_product(&(&aR * ypow[aR.len()]), &bL, y);

      let (mut dL, mut dR) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));

      let (G_L, G_R) = G_proof.split_at(aL.len());
      let (H_L, H_R) = H_proof.split_at(aL.len());

      let mut L_i = LR_statements(&(&aL * yinvpow[aL.len()]), G_R, &bR, H_L, cL, *H);
      L_i.push((dL, G));
      let L_i = prove_multiexp(&L_i);
      L.push(L_i);

      let mut R_i = LR_statements(&(&aR * ypow[aR.len()]), G_L, &bL, H_R, cR, *H);
      R_i.push((dR, G));
      let R_i = prove_multiexp(&R_i);
      R.push(R_i);

      let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
      let winv = w.invert().unwrap();

      G_proof = hadamard_fold(G_L, G_R, winv, w * yinvpow[aL.len()]);
      H_proof = hadamard_fold(H_L, H_R, w, winv);

      a = (&aL * w) + (aR * (winv * ypow[aL.len()]));
      b = (bL * winv) + (bR * w);

      alpha1 += (dL * (w * w)) + (dR * (winv * winv));

      dL.zeroize();
      dR.zeroize();
    }

    let mut r = Scalar::random(&mut *rng);
    let mut s = Scalar::random(&mut *rng);
    let mut d = Scalar::random(&mut *rng);
    let mut eta = Scalar::random(rng);

    let A1 = prove_multiexp(&[
      (r, G_proof[0]),
      (s, H_proof[0]),
      (d, G),
      ((r * y * b[0]) + (s * y * a[0]), *H),
    ]);
    let B = prove_multiexp(&[(r * y * s, *H), (eta, G)]);
    let e = hash_cache(&mut cache, &[A1.compress().to_bytes(), B.compress().to_bytes()]);

    let r1 = (a[0] * e) + r;
    r.zeroize();
    let s1 = (b[0] * e) + s;
    s.zeroize();
    let d1 = ((d * e) + eta) + (alpha1 * (e * e));
    d.zeroize();
    eta.zeroize();
    alpha1.zeroize();

    PlusStruct {
      A: *A,
      A1: *A1,
      B: *B,
      r1: *r1,
      s1: *s1,
      d1: *d1,
      L: L.drain(..).map(|L| *L).collect(),
      R: R.drain(..).map(|R| *R).collect(),
    }
  }

  #[must_use]
  fn verify_core<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, EdwardsPoint>,
    id: ID,
    commitments: &[DalekPoint],
  ) -> bool {
    // Verify commitments are valid
    if commitments.is_empty() || (commitments.len() > MAX_M) {
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
    let (mut cache, commitments) = hash_plus(commitments.iter().cloned());
    let y = hash_cache(&mut cache, &[self.A.compress().to_bytes()]);
    let yinv = y.invert().unwrap();
    let z = hash_to_scalar(&y.to_bytes());
    cache = z;

    let mut w = Vec::with_capacity(logMN);
    let mut winv = Vec::with_capacity(logMN);
    for (L, R) in self.L.iter().zip(&self.R) {
      w.push(hash_cache(&mut cache, &[L.compress().to_bytes(), R.compress().to_bytes()]));
      winv.push(cache.invert().unwrap());
    }

    let e = hash_cache(&mut cache, &[self.A1.compress().to_bytes(), self.B.compress().to_bytes()]);

    // Convert the proof from * INV_EIGHT to its actual form
    let normalize = |point: &DalekPoint| EdwardsPoint(point.mul_by_cofactor());

    let L = self.L.iter().map(normalize).collect::<Vec<_>>();
    let R = self.R.iter().map(normalize).collect::<Vec<_>>();
    let A = normalize(&self.A);
    let A1 = normalize(&self.A1);
    let B = normalize(&self.B);

    let mut commitments = commitments.iter().map(|c| c.mul_by_cofactor()).collect::<Vec<_>>();

    // Verify it
    let mut proof = Vec::with_capacity(logMN + 5 + (2 * (MN + logMN)));

    let mut yMN = y;
    for _ in 0 .. logMN {
      yMN *= yMN;
    }
    let yMNy = yMN * y;

    let (zpow, d) = d(z, M, MN);
    let zsq = zpow[0];

    let esq = e * e;
    let minus_esq = -esq;
    let commitment_weight = minus_esq * yMNy;
    for (i, commitment) in commitments.drain(..).enumerate() {
      proof.push((commitment_weight * zpow[i], commitment));
    }

    // Invert B, instead of the Scalar, as the latter is only 2x as expensive yet enables reduction
    // to a single addition under vartime for the first BP verified in the batch, which is expected
    // to be much more significant
    proof.push((Scalar::one(), -B));
    proof.push((-e, A1));
    proof.push((minus_esq, A));
    proof.push((Scalar(self.d1), G));

    let d_sum = zpow.sum() * Scalar::from(u64::MAX);
    let y_sum = weighted_powers(y, MN).sum();
    proof.push((
      Scalar(self.r1 * y.0 * self.s1) + (esq * ((yMNy * z * d_sum) + ((zsq - z) * y_sum))),
      *H,
    ));

    let w_cache = challenge_products(&w, &winv);

    let mut e_r1_y = e * Scalar(self.r1);
    let e_s1 = e * Scalar(self.s1);
    let esq_z = esq * z;
    let minus_esq_z = -esq_z;
    let mut minus_esq_y = minus_esq * yMN;

    for i in 0 .. MN {
      proof.push((e_r1_y * w_cache[i] + esq_z, GENERATORS.G[i]));
      proof.push((
        (e_s1 * w_cache[(!i) & (MN - 1)]) + minus_esq_z + (minus_esq_y * d[i]),
        GENERATORS.H[i],
      ));

      e_r1_y *= yinv;
      minus_esq_y *= yinv;
    }

    for i in 0 .. logMN {
      proof.push((minus_esq * w[i] * w[i], L[i]));
      proof.push((minus_esq * winv[i] * winv[i], R[i]));
    }

    verifier.queue(rng, id, proof);
    true
  }

  #[must_use]
  pub(crate) fn verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    commitments: &[DalekPoint],
  ) -> bool {
    let mut verifier = BatchVerifier::new(1);
    if self.verify_core(rng, &mut verifier, (), commitments) {
      verifier.verify_vartime()
    } else {
      false
    }
  }

  #[must_use]
  pub(crate) fn batch_verify<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, EdwardsPoint>,
    id: ID,
    commitments: &[DalekPoint],
  ) -> bool {
    self.verify_core(rng, verifier, id, commitments)
  }
}
