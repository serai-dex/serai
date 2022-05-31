#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use sha2::{Digest, Sha512};

use ff::Field;
use group::{Group, GroupEncoding};
use k256::{
  elliptic_curve::{bigint::{ArrayEncoding, U512}, ops::Reduce},
  Scalar, ProjectivePoint
};

use crate::spark::{F, G, H, U, GENERATORS_TRANSCRIPT};

#[cfg(feature = "frost")]
mod multisig;
#[cfg(feature = "frost")]
pub use multisig::ChaumMultisig;

#[derive(Clone, Debug)]
pub struct ChaumStatement {
  context: Vec<u8>,
  S_T: Vec<(ProjectivePoint, ProjectivePoint)>,
}

impl ChaumStatement {
  pub fn new(context: Vec<u8>, S_T: Vec<(ProjectivePoint, ProjectivePoint)>) -> ChaumStatement {
    ChaumStatement { context, S_T }
  }

  fn transcript(&self) -> Vec<u8> {
    let mut transcript = self.context.clone();
    for S_T in &self.S_T {
      transcript.extend(S_T.0.to_bytes());
      transcript.extend(S_T.1.to_bytes());
    }
    transcript
  }
}

#[derive(Clone, Debug)]
pub struct ChaumWitness {
  statement: ChaumStatement,
  xz: Vec<(Scalar, Scalar)>
}

impl ChaumWitness {
  pub fn new(statement: ChaumStatement, xz: Vec<(Scalar, Scalar)>) -> ChaumWitness {
    assert!(statement.S_T.len() != 0);
    assert_eq!(statement.S_T.len(), xz.len());
    ChaumWitness { statement, xz }
  }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ChaumCommitments {
  A1: ProjectivePoint,
  A2: Vec<ProjectivePoint>
}

impl ChaumCommitments {
  fn transcript(&self) -> Vec<u8> {
    let mut transcript = Vec::with_capacity((self.A2.len() + 1) * 33);
    transcript.extend(self.A1.to_bytes());
    for A in &self.A2 {
      transcript.extend(A.to_bytes());
    }
    transcript
  }
}

#[derive(Clone, PartialEq, Debug)]
pub struct ChaumProof {
  commitments: ChaumCommitments,
  t1: Vec<Scalar>,
  t2: Scalar,
  t3: Scalar
}

impl ChaumProof {
  fn r_t_commitments<R: RngCore + CryptoRng>(
    rng: &mut R,
    witness: &ChaumWitness
  ) -> (Vec<Scalar>, Scalar, ChaumCommitments) {
    let len = witness.xz.len();
    let mut rs = Vec::with_capacity(len);
    let mut r_sum = Scalar::zero();

    let mut commitments = ChaumCommitments {
      A1: ProjectivePoint::IDENTITY,
      A2: Vec::with_capacity(len)
    };

    for (_, T) in &witness.statement.S_T {
      let r = Scalar::random(&mut *rng);
      r_sum += r;
      commitments.A2.push(T * &r);
      rs.push(r);
    }

    let t = Scalar::random(&mut *rng);
    commitments.A1 = (*F * r_sum) + (*H * t);

    (rs, t, commitments)
  }

  fn t_prove(
    witness: &ChaumWitness,
    rs: &[Scalar],
    mut t3: Scalar,
    commitments: ChaumCommitments,
    nonces: &[Scalar],
    y: &Scalar
  ) -> (Scalar, ChaumProof) {
    let challenge = ChaumProof::challenge(&witness.statement, &commitments);
    let mut t1 = Vec::with_capacity(rs.len());
    let mut t2 = Scalar::zero();

    let mut accum = challenge;
    for (i, (x, z)) in witness.xz.iter().enumerate() {
      t1.push(rs[i] + (accum * x));
      t2 += nonces[i] + (accum * y);
      t3 += accum * z;
      accum *= challenge;
    }

    (challenge, ChaumProof { commitments, t1, t2, t3 })
  }

  fn challenge(statement: &ChaumStatement, commitments: &ChaumCommitments) -> Scalar {
    let mut transcript = b"Chaum".to_vec();
    transcript.extend(&*GENERATORS_TRANSCRIPT);
    transcript.extend(&statement.transcript());
    transcript.extend(&commitments.transcript());
    Scalar::from_uint_reduced(U512::from_be_byte_array(Sha512::digest(transcript)))
  }

  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    witness: &ChaumWitness,
    y: &Scalar
  ) -> ChaumProof {
    let len = witness.xz.len();
    let (rs, t3, mut commitments) = Self::r_t_commitments(rng, witness);

    let mut s_sum = Scalar::zero();
    let mut ss = Vec::with_capacity(len);
    for i in 0 .. len {
      let s = Scalar::random(&mut *rng);
      s_sum += s;
      commitments.A2[i] += *G * s;
      ss.push(s);
    }
    commitments.A1 += *G * s_sum;

    let (_, proof) = Self::t_prove(&witness, &rs, t3, commitments, &ss, y);
    proof
  }

  pub fn verify(&self, statement: &ChaumStatement) -> bool {
    let len = statement.S_T.len();
    assert_eq!(len, self.commitments.A2.len());
    assert_eq!(len, self.t1.len());

    let challenge = Self::challenge(&statement, &self.commitments);

    let mut one = self.commitments.A1 - ((*G * self.t2) + (*H * self.t3));
    let mut two = -(*G * self.t2);

    let mut accum = challenge;
    for i in 0 .. len {
      one += statement.S_T[i].0 * accum;
      one -= *F * self.t1[i];

      two += self.commitments.A2[i] + (*U * accum);
      two -= statement.S_T[i].1 * self.t1[i];
      accum *= challenge;
    }

    one.is_identity().into() && two.is_identity().into()
  }
}
