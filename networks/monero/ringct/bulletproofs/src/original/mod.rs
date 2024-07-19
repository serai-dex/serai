use std_shims::{sync::OnceLock, vec::Vec};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar, EdwardsPoint};

use monero_generators::{H, Generators, MAX_COMMITMENTS, COMMITMENT_BITS};
use monero_primitives::{Commitment, INV_EIGHT, keccak256_to_scalar};
use crate::{core::multiexp, scalar_vector::ScalarVector, BulletproofsBatchVerifier};

pub(crate) mod inner_product;
use inner_product::*;
pub(crate) use inner_product::IpProof;

include!(concat!(env!("OUT_DIR"), "/generators.rs"));

#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement<'a> {
  commitments: &'a [EdwardsPoint],
}

#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeWitness {
  commitments: Vec<Commitment>,
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRangeProof {
  pub(crate) A: EdwardsPoint,
  pub(crate) S: EdwardsPoint,
  pub(crate) T1: EdwardsPoint,
  pub(crate) T2: EdwardsPoint,
  pub(crate) tau_x: Scalar,
  pub(crate) mu: Scalar,
  pub(crate) t_hat: Scalar,
  pub(crate) ip: IpProof,
}

impl<'a> AggregateRangeStatement<'a> {
  pub(crate) fn new(commitments: &'a [EdwardsPoint]) -> Option<Self> {
    if commitments.is_empty() || (commitments.len() > MAX_COMMITMENTS) {
      None?;
    }
    Some(Self { commitments })
  }
}

impl AggregateRangeWitness {
  pub(crate) fn new(commitments: Vec<Commitment>) -> Option<Self> {
    if commitments.is_empty() || (commitments.len() > MAX_COMMITMENTS) {
      None?;
    }
    Some(Self { commitments })
  }
}

impl<'a> AggregateRangeStatement<'a> {
  fn initial_transcript(&self) -> (Scalar, Vec<EdwardsPoint>) {
    let V = self.commitments.iter().map(|c| c * INV_EIGHT()).collect::<Vec<_>>();
    (keccak256_to_scalar(V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>()), V)
  }

  fn transcript_A_S(transcript: Scalar, A: EdwardsPoint, S: EdwardsPoint) -> (Scalar, Scalar) {
    let mut buf = Vec::with_capacity(96);
    buf.extend(transcript.to_bytes());
    buf.extend(A.compress().to_bytes());
    buf.extend(S.compress().to_bytes());
    let y = keccak256_to_scalar(buf);
    let z = keccak256_to_scalar(y.to_bytes());
    (y, z)
  }

  fn transcript_T12(transcript: Scalar, T1: EdwardsPoint, T2: EdwardsPoint) -> Scalar {
    let mut buf = Vec::with_capacity(128);
    buf.extend(transcript.to_bytes());
    buf.extend(transcript.to_bytes());
    buf.extend(T1.compress().to_bytes());
    buf.extend(T2.compress().to_bytes());
    keccak256_to_scalar(buf)
  }

  fn transcript_tau_x_mu_t_hat(
    transcript: Scalar,
    tau_x: Scalar,
    mu: Scalar,
    t_hat: Scalar,
  ) -> Scalar {
    let mut buf = Vec::with_capacity(128);
    buf.extend(transcript.to_bytes());
    buf.extend(transcript.to_bytes());
    buf.extend(tau_x.to_bytes());
    buf.extend(mu.to_bytes());
    buf.extend(t_hat.to_bytes());
    keccak256_to_scalar(buf)
  }

  #[allow(clippy::needless_pass_by_value)]
  pub(crate) fn prove(
    self,
    rng: &mut (impl RngCore + CryptoRng),
    witness: AggregateRangeWitness,
  ) -> Option<AggregateRangeProof> {
    if self.commitments != witness.commitments.iter().map(Commitment::calculate).collect::<Vec<_>>()
    {
      None?
    };

    let generators = GENERATORS();

    let (mut transcript, _) = self.initial_transcript();

    // Find out the padded amount of commitments
    let mut padded_pow_of_2 = 1;
    while padded_pow_of_2 < witness.commitments.len() {
      padded_pow_of_2 <<= 1;
    }

    let mut aL = ScalarVector::new(padded_pow_of_2 * COMMITMENT_BITS);
    for (i, commitment) in witness.commitments.iter().enumerate() {
      let mut amount = commitment.amount;
      for j in 0 .. COMMITMENT_BITS {
        aL[(i * COMMITMENT_BITS) + j] = Scalar::from(amount & 1);
        amount >>= 1;
      }
    }
    let aR = aL.clone() - Scalar::ONE;

    let alpha = Scalar::random(&mut *rng);

    let A = {
      let mut terms = Vec::with_capacity(1 + (2 * aL.len()));
      terms.push((alpha, ED25519_BASEPOINT_POINT));
      for (aL, G) in aL.0.iter().zip(&generators.G) {
        terms.push((*aL, *G));
      }
      for (aR, H) in aR.0.iter().zip(&generators.H) {
        terms.push((*aR, *H));
      }
      let res = multiexp(&terms) * INV_EIGHT();
      terms.zeroize();
      res
    };

    let mut sL = ScalarVector::new(padded_pow_of_2 * COMMITMENT_BITS);
    let mut sR = ScalarVector::new(padded_pow_of_2 * COMMITMENT_BITS);
    for i in 0 .. (padded_pow_of_2 * COMMITMENT_BITS) {
      sL[i] = Scalar::random(&mut *rng);
      sR[i] = Scalar::random(&mut *rng);
    }
    let rho = Scalar::random(&mut *rng);

    let S = {
      let mut terms = Vec::with_capacity(1 + (2 * sL.len()));
      terms.push((rho, ED25519_BASEPOINT_POINT));
      for (sL, G) in sL.0.iter().zip(&generators.G) {
        terms.push((*sL, *G));
      }
      for (sR, H) in sR.0.iter().zip(&generators.H) {
        terms.push((*sR, *H));
      }
      let res = multiexp(&terms) * INV_EIGHT();
      terms.zeroize();
      res
    };

    let (y, z) = Self::transcript_A_S(transcript, A, S);
    transcript = z;
    let z = ScalarVector::powers(z, 3 + padded_pow_of_2);

    let twos = ScalarVector::powers(Scalar::from(2u8), COMMITMENT_BITS);

    let l = [aL - z[1], sL];
    let y_pow_n = ScalarVector::powers(y, aR.len());
    let mut r = [((aR + z[1]) * &y_pow_n), sR * &y_pow_n];
    {
      for j in 0 .. padded_pow_of_2 {
        for i in 0 .. COMMITMENT_BITS {
          r[0].0[(j * COMMITMENT_BITS) + i] += z[2 + j] * twos[i];
        }
      }
    }
    let t1 = (l[0].clone().inner_product(&r[1])) + (r[0].clone().inner_product(&l[1]));
    let t2 = l[1].clone().inner_product(&r[1]);

    let tau_1 = Scalar::random(&mut *rng);
    let T1 = {
      let mut T1_terms = [(t1, H()), (tau_1, ED25519_BASEPOINT_POINT)];
      for term in &mut T1_terms {
        term.0 *= INV_EIGHT();
      }
      let T1 = multiexp(&T1_terms);
      T1_terms.zeroize();
      T1
    };
    let tau_2 = Scalar::random(&mut *rng);
    let T2 = {
      let mut T2_terms = [(t2, H()), (tau_2, ED25519_BASEPOINT_POINT)];
      for term in &mut T2_terms {
        term.0 *= INV_EIGHT();
      }
      let T2 = multiexp(&T2_terms);
      T2_terms.zeroize();
      T2
    };

    transcript = Self::transcript_T12(transcript, T1, T2);
    let x = transcript;

    let [l0, l1] = l;
    let l = l0 + &(l1 * x);
    let [r0, r1] = r;
    let r = r0 + &(r1 * x);
    let t_hat = l.clone().inner_product(&r);
    let mut tau_x = ((tau_2 * x) + tau_1) * x;
    {
      for (i, commitment) in witness.commitments.iter().enumerate() {
        tau_x += z[2 + i] * commitment.mask;
      }
    }
    let mu = alpha + (rho * x);

    let y_inv_pow_n = ScalarVector::powers(y.invert(), l.len());

    transcript = Self::transcript_tau_x_mu_t_hat(transcript, tau_x, mu, t_hat);
    let x_ip = transcript;

    let ip = IpStatement::new_without_P_transcript(y_inv_pow_n, x_ip)
      .prove(transcript, IpWitness::new(l, r).unwrap())
      .unwrap();

    let res = AggregateRangeProof { A, S, T1, T2, tau_x, mu, t_hat, ip };
    #[cfg(debug_assertions)]
    {
      let mut verifier = BulletproofsBatchVerifier::default();
      debug_assert!(self.verify(rng, &mut verifier, res.clone()));
      debug_assert!(verifier.verify());
    }
    Some(res)
  }

  #[must_use]
  pub(crate) fn verify(
    self,
    rng: &mut (impl RngCore + CryptoRng),
    verifier: &mut BulletproofsBatchVerifier,
    mut proof: AggregateRangeProof,
  ) -> bool {
    let mut padded_pow_of_2 = 1;
    while padded_pow_of_2 < self.commitments.len() {
      padded_pow_of_2 <<= 1;
    }
    let ip_rows = padded_pow_of_2 * COMMITMENT_BITS;

    while verifier.0.g_bold.len() < ip_rows {
      verifier.0.g_bold.push(Scalar::ZERO);
      verifier.0.h_bold.push(Scalar::ZERO);
    }

    let (mut transcript, mut commitments) = self.initial_transcript();
    for commitment in &mut commitments {
      *commitment = commitment.mul_by_cofactor();
    }

    let (y, z) = Self::transcript_A_S(transcript, proof.A, proof.S);
    transcript = z;
    let z = ScalarVector::powers(z, 3 + padded_pow_of_2);
    transcript = Self::transcript_T12(transcript, proof.T1, proof.T2);
    let x = transcript;
    transcript = Self::transcript_tau_x_mu_t_hat(transcript, proof.tau_x, proof.mu, proof.t_hat);
    let x_ip = transcript;

    proof.A = proof.A.mul_by_cofactor();
    proof.S = proof.S.mul_by_cofactor();
    proof.T1 = proof.T1.mul_by_cofactor();
    proof.T2 = proof.T2.mul_by_cofactor();

    let y_pow_n = ScalarVector::powers(y, ip_rows);
    let y_inv_pow_n = ScalarVector::powers(y.invert(), ip_rows);

    let twos = ScalarVector::powers(Scalar::from(2u8), COMMITMENT_BITS);

    // 65
    {
      let weight = Scalar::random(&mut *rng);
      verifier.0.h += weight * proof.t_hat;
      verifier.0.g += weight * proof.tau_x;

      // Now that we've accumulated the lhs, negate the weight and accumulate the rhs
      // These will now sum to 0 if equal
      let weight = -weight;

      verifier.0.h += weight * (z[1] - (z[2])) * y_pow_n.sum();

      for (i, commitment) in commitments.iter().enumerate() {
        verifier.0.other.push((weight * z[2 + i], *commitment));
      }

      for i in 0 .. padded_pow_of_2 {
        verifier.0.h -= weight * z[3 + i] * twos.clone().sum();
      }
      verifier.0.other.push((weight * x, proof.T1));
      verifier.0.other.push((weight * (x * x), proof.T2));
    }

    let ip_weight = Scalar::random(&mut *rng);

    // 66
    verifier.0.other.push((ip_weight, proof.A));
    verifier.0.other.push((ip_weight * x, proof.S));
    // We can replace these with a g_sum, h_sum scalar in the batch verifier
    // It'd trade `2 * ip_rows` scalar additions (per proof) for one scalar addition and an
    // additional term in the MSM
    let ip_z = ip_weight * z[1];
    for i in 0 .. ip_rows {
      verifier.0.h_bold[i] += ip_z;
    }
    let neg_ip_z = -ip_z;
    for i in 0 .. ip_rows {
      verifier.0.g_bold[i] += neg_ip_z;
    }
    {
      for j in 0 .. padded_pow_of_2 {
        for i in 0 .. COMMITMENT_BITS {
          let full_i = (j * COMMITMENT_BITS) + i;
          verifier.0.h_bold[full_i] += ip_weight * y_inv_pow_n[full_i] * z[2 + j] * twos[i];
        }
      }
    }
    verifier.0.h += ip_weight * x_ip * proof.t_hat;

    // 67, 68
    verifier.0.g += ip_weight * -proof.mu;
    let res = IpStatement::new_without_P_transcript(y_inv_pow_n, x_ip)
      .verify(verifier, ip_rows, transcript, ip_weight, proof.ip);
    res.is_ok()
  }
}
