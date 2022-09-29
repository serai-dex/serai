use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use curve25519_dalek::{scalar::Scalar as DalekScalar, edwards::EdwardsPoint as DalekPoint};

use group::{ff::Field, Group};
use dalek_ff_group::{ED25519_BASEPOINT_POINT as G, Scalar, EdwardsPoint};

use multiexp::BatchVerifier;

use crate::{Commitment, ringct::bulletproofs::core::*};

include!(concat!(env!("OUT_DIR"), "/generators.rs"));

lazy_static! {
  static ref ONE_N: ScalarVector = ScalarVector(vec![Scalar::one(); N]);
  static ref IP12: Scalar = inner_product(&ONE_N, &TWO_N);
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OriginalStruct {
  pub(crate) A: DalekPoint,
  pub(crate) S: DalekPoint,
  pub(crate) T1: DalekPoint,
  pub(crate) T2: DalekPoint,
  pub(crate) taux: DalekScalar,
  pub(crate) mu: DalekScalar,
  pub(crate) L: Vec<DalekPoint>,
  pub(crate) R: Vec<DalekPoint>,
  pub(crate) a: DalekScalar,
  pub(crate) b: DalekScalar,
  pub(crate) t: DalekScalar,
}

impl OriginalStruct {
  pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: &[Commitment],
  ) -> OriginalStruct {
    let (logMN, M, MN) = MN(commitments.len());

    let (aL, aR) = bit_decompose(commitments);
    let (mut cache, _) = hash_commitments(commitments.iter().map(Commitment::calculate));

    let (sL, sR) =
      ScalarVector((0 .. (MN * 2)).map(|_| Scalar::random(&mut *rng)).collect::<Vec<_>>()).split();

    let (mut alpha, A) = alpha_rho(&mut *rng, &GENERATORS, &aL, &aR);
    let (mut rho, S) = alpha_rho(&mut *rng, &GENERATORS, &sL, &sR);

    let y = hash_cache(&mut cache, &[A.compress().to_bytes(), S.compress().to_bytes()]);
    let mut cache = hash_to_scalar(&y.to_bytes());
    let z = cache;

    let l0 = &aL - z;
    let l1 = sL;

    let mut zero_twos = Vec::with_capacity(MN);
    let zpow = ScalarVector::powers(z, M + 2);
    for j in 0 .. M {
      for i in 0 .. N {
        zero_twos.push(zpow[j + 2] * TWO_N[i]);
      }
    }

    let yMN = ScalarVector::powers(y, MN);
    let r0 = (&(aR + z) * &yMN) + ScalarVector(zero_twos);
    let r1 = yMN * sR;

    let (T1, T2, x, mut taux) = {
      let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
      let t2 = inner_product(&l1, &r1);

      let mut tau1 = Scalar::random(&mut *rng);
      let mut tau2 = Scalar::random(rng);

      let T1 = prove_multiexp(&[(t1, *H), (tau1, EdwardsPoint::generator())]);
      let T2 = prove_multiexp(&[(t2, *H), (tau2, EdwardsPoint::generator())]);

      let x =
        hash_cache(&mut cache, &[z.to_bytes(), T1.compress().to_bytes(), T2.compress().to_bytes()]);

      let taux = (tau2 * (x * x)) + (tau1 * x);

      tau1.zeroize();
      tau2.zeroize();
      (T1, T2, x, taux)
    };

    let mu = (x * rho) + alpha;
    alpha.zeroize();
    rho.zeroize();

    for (i, gamma) in commitments.iter().map(|c| Scalar(c.mask)).enumerate() {
      taux += zpow[i + 2] * gamma;
    }

    let l = &l0 + &(l1 * x);
    let r = &r0 + &(r1 * x);

    let t = inner_product(&l, &r);

    let x_ip =
      hash_cache(&mut cache, &[x.to_bytes(), taux.to_bytes(), mu.to_bytes(), t.to_bytes()]);

    let mut a = l;
    let mut b = r;

    let yinv = y.invert().unwrap();
    let yinvpow = ScalarVector::powers(yinv, MN);

    let mut G_proof = GENERATORS.G[.. a.len()].to_vec();
    let mut H_proof = GENERATORS.H[.. a.len()].to_vec();
    H_proof.iter_mut().zip(yinvpow.0.iter()).for_each(|(this_H, yinvpow)| *this_H *= yinvpow);
    let U = *H * x_ip;

    let mut L = Vec::with_capacity(logMN);
    let mut R = Vec::with_capacity(logMN);

    while a.len() != 1 {
      let (aL, aR) = a.split();
      let (bL, bR) = b.split();

      let cL = inner_product(&aL, &bR);
      let cR = inner_product(&aR, &bL);

      let (G_L, G_R) = G_proof.split_at(aL.len());
      let (H_L, H_R) = H_proof.split_at(aL.len());

      let L_i = prove_multiexp(&LR_statements(&aL, G_R, &bR, H_L, cL, U));
      let R_i = prove_multiexp(&LR_statements(&aR, G_L, &bL, H_R, cR, U));
      L.push(L_i);
      R.push(R_i);

      let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
      let winv = w.invert().unwrap();

      a = (aL * w) + (aR * winv);
      b = (bL * winv) + (bR * w);

      if a.len() != 1 {
        G_proof = hadamard_fold(G_L, G_R, winv, w);
        H_proof = hadamard_fold(H_L, H_R, w, winv);
      }
    }

    OriginalStruct {
      A: *A,
      S: *S,
      T1: *T1,
      T2: *T2,
      taux: *taux,
      mu: *mu,
      L: L.drain(..).map(|L| *L).collect(),
      R: R.drain(..).map(|R| *R).collect(),
      a: *a[0],
      b: *b[0],
      t: *t,
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
    let (mut cache, commitments) = hash_commitments(commitments.iter().cloned());
    let y = hash_cache(&mut cache, &[self.A.compress().to_bytes(), self.S.compress().to_bytes()]);

    let z = hash_to_scalar(&y.to_bytes());
    cache = z;

    let x = hash_cache(
      &mut cache,
      &[z.to_bytes(), self.T1.compress().to_bytes(), self.T2.compress().to_bytes()],
    );

    let x_ip = hash_cache(
      &mut cache,
      &[x.to_bytes(), self.taux.to_bytes(), self.mu.to_bytes(), self.t.to_bytes()],
    );

    let mut w = Vec::with_capacity(logMN);
    let mut winv = Vec::with_capacity(logMN);
    for (L, R) in self.L.iter().zip(&self.R) {
      w.push(hash_cache(&mut cache, &[L.compress().to_bytes(), R.compress().to_bytes()]));
      winv.push(cache.invert().unwrap());
    }

    // Convert the proof from * INV_EIGHT to its actual form
    let normalize = |point: &DalekPoint| EdwardsPoint(point.mul_by_cofactor());

    let L = self.L.iter().map(normalize).collect::<Vec<_>>();
    let R = self.R.iter().map(normalize).collect::<Vec<_>>();
    let T1 = normalize(&self.T1);
    let T2 = normalize(&self.T2);
    let A = normalize(&self.A);
    let S = normalize(&self.S);

    let commitments = commitments.iter().map(|c| c.mul_by_cofactor()).collect::<Vec<_>>();

    // Verify it
    let mut proof = Vec::with_capacity(4 + commitments.len());

    let zpow = ScalarVector::powers(z, M + 3);
    let ip1y = ScalarVector::powers(y, M * N).sum();
    let mut k = -(zpow[2] * ip1y);
    for j in 1 ..= M {
      k -= zpow[j + 2] * *IP12;
    }
    let y1 = Scalar(self.t) - ((z * ip1y) + k);
    proof.push((-y1, *H));

    proof.push((-Scalar(self.taux), G));

    for (j, commitment) in commitments.iter().enumerate() {
      proof.push((zpow[j + 2], *commitment));
    }

    proof.push((x, T1));
    proof.push((x * x, T2));
    verifier.queue(&mut *rng, id, proof);

    proof = Vec::with_capacity(4 + (2 * (MN + logMN)));
    let z3 = (Scalar(self.t) - (Scalar(self.a) * Scalar(self.b))) * x_ip;
    proof.push((z3, *H));
    proof.push((-Scalar(self.mu), G));

    proof.push((Scalar::one(), A));
    proof.push((x, S));

    {
      let ypow = ScalarVector::powers(y, MN);
      let yinv = y.invert().unwrap();
      let yinvpow = ScalarVector::powers(yinv, MN);

      let w_cache = challenge_products(&w, &winv);

      for i in 0 .. MN {
        let g = (Scalar(self.a) * w_cache[i]) + z;
        proof.push((-g, GENERATORS.G[i]));

        let mut h = Scalar(self.b) * yinvpow[i] * w_cache[(!i) & (MN - 1)];
        h -= ((zpow[(i / N) + 2] * TWO_N[i % N]) + (z * ypow[i])) * yinvpow[i];
        proof.push((-h, GENERATORS.H[i]));
      }
    }

    for i in 0 .. logMN {
      proof.push((w[i] * w[i], L[i]));
      proof.push((winv[i] * winv[i], R[i]));
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
