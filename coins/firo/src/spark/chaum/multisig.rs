use std::io::Read;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use ff::Field;
use k256::{Scalar, ProjectivePoint};

use transcript::{Transcript, RecommendedTranscript};
use frost::{curve::Secp256k1, FrostError, FrostView, algorithm::Algorithm};

use crate::spark::{G, GENERATORS_TRANSCRIPT, chaum::{ChaumWitness, ChaumProof}};

#[derive(Clone)]
pub struct ChaumMultisig {
  transcript: RecommendedTranscript,
  len: usize,
  witness: ChaumWitness,

  challenge: Scalar,
  proof: Option<ChaumProof>
}

impl ChaumMultisig {
  pub fn new(mut transcript: RecommendedTranscript, witness: ChaumWitness) -> ChaumMultisig {
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

      challenge: Scalar::zero(),
      proof: None
    }
  }
}

impl Algorithm<Secp256k1> for ChaumMultisig {
  type Transcript = RecommendedTranscript;
  type Signature = ChaumProof;

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn nonces(&self) -> Vec<Vec<ProjectivePoint>> {
    vec![vec![*G]; self.len]
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _: &mut R,
    _: &FrostView<Secp256k1>
  ) -> Vec<u8> {
    vec![]
  }

  fn process_addendum<Re: Read>(
    &mut self,
    _: &FrostView<Secp256k1>,
    _: u16,
    _: &mut Re
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    view: &FrostView<Secp256k1>,
    nonce_sums: &[Vec<ProjectivePoint>],
    nonces: &[Scalar],
    _: &[u8]
  ) -> Scalar {
    let (rs, t3, mut commitments) = ChaumProof::r_t_commitments(
      &mut ChaCha12Rng::from_seed(self.transcript.rng_seed(b"r_t")),
      &self.witness
    );

    for i in 0 .. self.len {
      commitments.A2[i] += nonce_sums[i][0];
    }
    commitments.A1 += nonce_sums.iter().map(|sum| sum[0]).sum::<ProjectivePoint>();

    let (challenge, proof) = ChaumProof::t_prove(
      &self.witness,
      &rs,
      t3,
      commitments,
      nonces,
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
    _: &[Vec<ProjectivePoint>],
    sum: Scalar
  ) -> Option<Self::Signature> {
    let mut proof = self.proof.clone().unwrap();
    proof.t2 = sum;
    Some(proof).filter(|proof| proof.verify(&self.witness.statement))
  }

  fn verify_share(
    &self,
    _: u16,
    verification_share: ProjectivePoint,
    nonces: &[Vec<ProjectivePoint>],
    share: Scalar
  ) -> bool {
    let mut t2 = ProjectivePoint::IDENTITY;
    let mut accum = self.challenge;
    for i in 0 .. self.len {
      t2 += nonces[i][0] + (verification_share * accum);
      accum *= self.challenge;
    }
    (*G * share) == t2
  }
}
