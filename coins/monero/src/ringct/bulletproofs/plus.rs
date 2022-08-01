use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar as DalekScalar, edwards::EdwardsPoint as DalekPoint};

use group::ff::Field;
use dalek_ff_group::{ED25519_BASEPOINT_POINT as G, Scalar, EdwardsPoint};

use multiexp::BatchVerifier;

use crate::{
  Commitment, hash,
  ringct::{hash_to_point::raw_hash_to_point, bulletproofs::core::*},
};

lazy_static! {
  static ref GENERATORS: Generators = generators_core(b"bulletproof_plus");
  static ref TRANSCRIPT: [u8; 32] =
    EdwardsPoint(raw_hash_to_point(hash(b"bulletproof_plus_transcript"))).compress().to_bytes();
}

// TRANSCRIPT isn't a Scalar, so we need this alternative for the first hash
fn hash_plus(mash: &[u8]) -> Scalar {
  hash_to_scalar(&[&*TRANSCRIPT as &[u8], mash].concat())
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
    let (mut cache, _) = hash_commitments(commitments.iter().map(Commitment::calculate));
    cache = hash_plus(&cache.to_bytes());
    let (mut alpha1, A) = alpha_rho(&mut *rng, &GENERATORS, &aL, &aR);

    let y = hash_cache(&mut cache, &[A.compress().to_bytes()]);
    let mut cache = hash_to_scalar(&y.to_bytes());
    let z = cache;

    let zpow = ScalarVector::even_powers(z, 2 * M);
    // d[j*N+i] = z**(2*(j+1)) * 2**i
    let mut d = vec![Scalar::zero(); MN];
    for j in 0 .. M {
      for i in 0 .. N {
        d[(j * N) + i] = zpow[j] * TWO_N[i];
      }
    }

    let aL1 = aL - z;

    let ypow = ScalarVector::powers(y, MN + 2);
    let mut y_for_d = ScalarVector(ypow.0[1 ..= MN].to_vec());
    y_for_d.0.reverse();
    let aR1 = (aR + z) + (y_for_d * ScalarVector(d));

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

      let (dL, dR) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));

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
    }

    let r = Scalar::random(&mut *rng);
    let s = Scalar::random(&mut *rng);
    let d = Scalar::random(&mut *rng);
    let eta = Scalar::random(rng);

    let A1 = prove_multiexp(&[
      (r, G_proof[0]),
      (s, H_proof[0]),
      (d, G),
      ((r * y * b[0]) + (s * y * a[0]), *H),
    ]);
    let B = prove_multiexp(&[(r * y * s, *H), (eta, G)]);
    let e = hash_cache(&mut cache, &[A1.compress().to_bytes(), B.compress().to_bytes()]);

    let r1 = (a[0] * e) + r;
    let s1 = (b[0] * e) + s;
    let d1 = ((d * e) + eta) + (alpha1 * (e * e));

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
  fn verify_core<ID: Copy, R: RngCore + CryptoRng>(
    &self,
    _rng: &mut R,
    _verifier: &mut BatchVerifier<ID, EdwardsPoint>,
    _id: ID,
    _commitments: &[DalekPoint],
  ) -> bool {
    unimplemented!("Bulletproofs+ verification isn't implemented")
  }

  #[must_use]
  pub(crate) fn verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    commitments: &[DalekPoint],
  ) -> bool {
    let mut verifier = BatchVerifier::new(4 + commitments.len() + 4 + (2 * (MAX_MN + 10)));
    if self.verify_core(rng, &mut verifier, (), commitments) {
      verifier.verify_vartime()
    } else {
      false
    }
  }

  #[must_use]
  pub(crate) fn batch_verify<ID: Copy, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, EdwardsPoint>,
    id: ID,
    commitments: &[DalekPoint],
  ) -> bool {
    self.verify_core(rng, verifier, id, commitments)
  }
}
