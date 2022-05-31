use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use ff::Field;
use group::GroupEncoding;
use k256::{Scalar, ProjectivePoint};

use transcript::Transcript as _;
use frost::{CurveError, Curve, FrostError, MultisigView, algorithm::Algorithm};

use crate::spark::{
  G, GENERATORS_TRANSCRIPT,
  frost::{Transcript, Secp256k1},
  chaum::{ChaumWitness, ChaumProof}
};

#[derive(Clone)]
pub struct ChaumMultisig {
  transcript: Transcript,
  len: usize,
  witness: ChaumWitness,

  // The following is ugly as hell as it's re-implementing the nonce code FROST is meant to handle
  // Using FROST's provided SchnorrSignature algorithm multiple times would work, handling nonces
  // for us, except you need the commitments for the challenge which means you need the binding
  // factors, which means then you're re-calculating those, and...
  // The best solution would be for FROST itself to support multi-nonce protocols, if there is
  // sufficient reason for it to
  additional_nonces: Vec<(Scalar, Scalar)>,
  nonces: HashMap<u16, Vec<(ProjectivePoint, ProjectivePoint)>>,
  sum: Vec<(ProjectivePoint, ProjectivePoint)>,

  challenge: Scalar,
  binding: Scalar,
  proof: Option<ChaumProof>
}

impl ChaumMultisig {
  pub fn new(mut transcript: Transcript, witness: ChaumWitness) -> ChaumMultisig {
    transcript.domain_separate(b"Chaum");
    transcript.append_message(b"generators", &*GENERATORS_TRANSCRIPT);
    transcript.append_message(b"statement", &witness.statement.transcript());
    for (x, z) in &witness.xz {
      transcript.append_message(b"x", &x.to_bytes());
      transcript.append_message(b"z", &z.to_bytes());
    }

    let len = witness.xz.len();
    ChaumMultisig {
      transcript,
      len,
      witness,

      additional_nonces: Vec::with_capacity(len - 1),
      nonces: HashMap::new(),
      sum: vec![(ProjectivePoint::IDENTITY, ProjectivePoint::IDENTITY); len - 1],

      binding: Scalar::zero(),
      challenge: Scalar::zero(),
      proof: None
    }
  }
}

impl Algorithm<Secp256k1> for ChaumMultisig {
  type Transcript = Transcript;
  type Signature = ChaumProof;

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    _: &MultisigView<Secp256k1>,
    _: &[Scalar; 2],
  ) -> Vec<u8> {
    // While FROST will provide D_0 and E_0, we need D_i and E_i
    let mut res = Vec::with_capacity((self.len - 1) * 33);
    for _ in 1 .. self.len {
      let d = Scalar::random(&mut *rng);
      let e = Scalar::random(&mut *rng);
      res.extend(&(*G * d).to_bytes());
      res.extend(&(*G * e).to_bytes());
      self.additional_nonces.push((d, e));
    }
    res
  }

  fn process_addendum(
    &mut self,
    _: &MultisigView<Secp256k1>,
    l: u16,
    _: &[ProjectivePoint; 2],
    addendum: &[u8],
  ) -> Result<(), FrostError> {
    let mut nonces = Vec::with_capacity(self.len - 1);
    for i in 0 .. (self.len - 1) {
      let p = i * 2;
      let (D, E) = (|| Ok((
        Secp256k1::G_from_slice(&addendum[(p * 33) .. ((p + 1) * 33)])?,
        Secp256k1::G_from_slice(&addendum[((p + 1) * 33) .. ((p + 2) * 33)])?
      )))().map_err(|_: CurveError| FrostError::InvalidCommitment(l))?;
      self.transcript.append_message(b"participant", &l.to_be_bytes());
      self.transcript.append_message(b"commitment_D_additional", &D.to_bytes());
      self.transcript.append_message(b"commitment_E_additional", &E.to_bytes());
      self.sum[i].0 += D;
      self.sum[i].1 += E;
      nonces.push((D, E));
    }
    self.nonces.insert(l, nonces);
    Ok(())
  }

  fn sign_share(
    &mut self,
    view: &MultisigView<Secp256k1>,
    sum_0: ProjectivePoint,
    binding: Scalar,
    nonce_0: Scalar,
    _: &[u8],
  ) -> Scalar {
    self.binding = binding;

    let (rs, t3, mut commitments) = ChaumProof::r_t_commitments(
      &mut ChaCha12Rng::from_seed(self.transcript.rng_seed(b"r_t")),
      &self.witness
    );

    let mut sum = ProjectivePoint::IDENTITY;
    for i in 0 .. self.len {
      let nonce = if i == 0 {
        sum_0
      } else {
        self.sum[i - 1].0 + (self.sum[i - 1].1 * binding)
      };
      commitments.A2[i] += nonce;
      sum += nonce;
    }
    commitments.A1 += sum;

    let mut nonces = Vec::with_capacity(self.len);
    for i in 0 .. self.len {
      nonces.push(
        if i == 0 {
          nonce_0
        } else {
          self.additional_nonces[i - 1].0 + (self.additional_nonces[i - 1].1 * binding)
        }
      );
    }

    let (challenge, proof) = ChaumProof::t_prove(
      &self.witness,
      &rs,
      t3,
      commitments,
      &nonces,
      &view.secret_share()
    );
    self.challenge = challenge;
    let t2 = proof.t2;
    self.proof = Some(proof);
    t2
  }

  fn verify(
    &self,
    _: ProjectivePoint,
    _: ProjectivePoint,
    sum: Scalar
  ) -> Option<Self::Signature> {
    let mut proof = self.proof.clone().unwrap();
    proof.t2 = sum;
    Some(proof).filter(|proof| proof.verify(&self.witness.statement))
  }

  fn verify_share(
    &self,
    l: u16,
    verification_share: ProjectivePoint,
    nonce: ProjectivePoint,
    share: Scalar,
  ) -> bool {
    let mut t2 = ProjectivePoint::IDENTITY;
    let mut accum = self.challenge;
    for i in 0 .. self.len {
      let nonce = if i == 0 {
        nonce
      } else {
        self.nonces[&l][i - 1].0 + (self.nonces[&l][i - 1].1 * self.binding)
      };
      t2 += nonce + (verification_share * accum);
      accum *= self.challenge;
    }

    (*G * share) == t2
  }
}
