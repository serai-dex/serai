use core::fmt::Debug;
use std::sync::{Arc, RwLock};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::Identity,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use group::Group;

use transcript::{Transcript, RecommendedTranscript};
use frost::{curve::Ed25519, FrostError, FrostView, algorithm::Algorithm};
use dalek_ff_group as dfg;

use crate::{
  hash_to_point,
  frost::{MultisigError, write_dleq, read_dleq},
  ringct::clsag::{ClsagInput, Clsag}
};

impl ClsagInput {
  fn transcript<T: Transcript>(&self, transcript: &mut T) {
    // Doesn't domain separate as this is considered part of the larger CLSAG proof

    // Ring index
    transcript.append_message(b"ring_index", &[self.decoys.i]);

    // Ring
    let mut ring = vec![];
    for pair in &self.decoys.ring {
      // Doesn't include global output indexes as CLSAG doesn't care and won't be affected by it
      // They're just a unreliable reference to this data which will be included in the message
      // if in use
      ring.extend(&pair[0].compress().to_bytes());
      ring.extend(&pair[1].compress().to_bytes());
    }
    transcript.append_message(b"ring", &ring);

    // Doesn't include the commitment's parts as the above ring + index includes the commitment
    // The only potential malleability would be if the G/H relationship is known breaking the
    // discrete log problem, which breaks everything already
  }
}

#[derive(Clone, Debug)]
pub struct ClsagDetails {
  input: ClsagInput,
  mask: Scalar
}

impl ClsagDetails {
  pub fn new(input: ClsagInput, mask: Scalar) -> ClsagDetails {
    ClsagDetails { input, mask }
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Debug)]
struct Interim {
  p: Scalar,
  c: Scalar,

  clsag: Clsag,
  pseudo_out: EdwardsPoint
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct ClsagMultisig {
  transcript: RecommendedTranscript,

  H: EdwardsPoint,
  // Merged here as CLSAG needs it, passing it would be a mess, yet having it beforehand requires a round
  image: EdwardsPoint,
  AH: (dfg::EdwardsPoint, dfg::EdwardsPoint),

  details: Arc<RwLock<Option<ClsagDetails>>>,

  msg: Option<[u8; 32]>,
  interim: Option<Interim>
}

impl ClsagMultisig {
  pub fn new(
    transcript: RecommendedTranscript,
    details: Arc<RwLock<Option<ClsagDetails>>>
  ) -> Result<ClsagMultisig, MultisigError> {
    Ok(
      ClsagMultisig {
        transcript,

        H: EdwardsPoint::identity(),
        image: EdwardsPoint::identity(),
        AH: (dfg::EdwardsPoint::identity(), dfg::EdwardsPoint::identity()),

        details,

        msg: None,
        interim: None
      }
    )
  }

  pub fn serialized_len() -> usize {
    3 * (32 + 64)
  }

  fn input(&self) -> ClsagInput {
    (*self.details.read().unwrap()).as_ref().unwrap().input.clone()
  }

  fn mask(&self) -> Scalar {
    (*self.details.read().unwrap()).as_ref().unwrap().mask
  }
}

impl Algorithm<Ed25519> for ClsagMultisig {
  type Transcript = RecommendedTranscript;
  type Signature = (Clsag, EdwardsPoint);

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    view: &FrostView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    self.H = hash_to_point(&view.group_key().0);

    let mut serialized = Vec::with_capacity(ClsagMultisig::serialized_len());
    serialized.extend((view.secret_share().0 * self.H).compress().to_bytes());
    serialized.extend(write_dleq(rng, self.H, view.secret_share().0));

    serialized.extend((nonces[0].0 * self.H).compress().to_bytes());
    serialized.extend(write_dleq(rng, self.H, nonces[0].0));
    serialized.extend((nonces[1].0 * self.H).compress().to_bytes());
    serialized.extend(write_dleq(rng, self.H, nonces[1].0));
    serialized
  }

  fn process_addendum(
    &mut self,
    view: &FrostView<Ed25519>,
    l: u16,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    if serialized.len() != ClsagMultisig::serialized_len() {
      // Not an optimal error but...
      Err(FrostError::InvalidCommitment(l))?;
    }

    if self.AH.0.is_identity().into() {
      self.transcript.domain_separate(b"CLSAG");
      self.input().transcript(&mut self.transcript);
      self.transcript.append_message(b"mask", &self.mask().to_bytes());
    }

    // Uses the same format FROST does for the expected commitments (nonce * G where this is nonce * H)
    // The following technically shouldn't need to be committed to, as we've committed to equivalents,
    // yet it doesn't hurt and may resolve some unknown issues
    self.transcript.append_message(b"participant", &l.to_be_bytes());

    let mut cursor = 0;
    self.transcript.append_message(b"image_share", &serialized[cursor .. (cursor + 32)]);
    self.image += read_dleq(
      serialized,
      cursor,
      self.H,
      l,
      view.verification_share(l)
    ).map_err(|_| FrostError::InvalidCommitment(l))?.0;
    cursor += 96;

    self.transcript.append_message(b"commitment_D_H", &serialized[cursor .. (cursor + 32)]);
    self.AH.0 += read_dleq(serialized, cursor, self.H, l, commitments[0]).map_err(|_| FrostError::InvalidCommitment(l))?;
    cursor += 96;

    self.transcript.append_message(b"commitment_E_H", &serialized[cursor .. (cursor + 32)]);
    self.AH.1 += read_dleq(serialized, cursor, self.H, l, commitments[1]).map_err(|_| FrostError::InvalidCommitment(l))?;

    Ok(())
  }

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn sign_share(
    &mut self,
    view: &FrostView<Ed25519>,
    nonce_sum: dfg::EdwardsPoint,
    b: dfg::Scalar,
    nonce: dfg::Scalar,
    msg: &[u8]
  ) -> dfg::Scalar {
    // Apply the binding factor to the H variant of the nonce
    self.AH.0 += self.AH.1 * b;

    // Use the transcript to get a seeded random number generator
    // The transcript contains private data, preventing passive adversaries from recreating this
    // process even if they have access to commitments (specifically, the ring index being signed
    // for, along with the mask which should not only require knowing the shared keys yet also the
    // input commitment masks)
    let mut rng = ChaCha12Rng::from_seed(self.transcript.rng_seed(b"decoy_responses"));

    self.msg = Some(msg.try_into().expect("CLSAG message should be 32-bytes"));

    #[allow(non_snake_case)]
    let (clsag, pseudo_out, p, c) = Clsag::sign_core(
      &mut rng,
      &self.image,
      &self.input(),
      self.mask(),
      &self.msg.as_ref().unwrap(),
      nonce_sum.0,
      self.AH.0.0
    );
    self.interim = Some(Interim { p, c, clsag, pseudo_out });

    let share = dfg::Scalar(nonce.0 - (p * view.secret_share().0));

    share
  }

  fn verify(
    &self,
    _: dfg::EdwardsPoint,
    _: dfg::EdwardsPoint,
    sum: dfg::Scalar
  ) -> Option<Self::Signature> {
    let interim = self.interim.as_ref().unwrap();
    let mut clsag = interim.clsag.clone();
    clsag.s[usize::from(self.input().decoys.i)] = sum.0 - interim.c;
    if clsag.verify(
      &self.input().decoys.ring,
      &self.image,
      &interim.pseudo_out,
      &self.msg.as_ref().unwrap()
    ).is_ok() {
      return Some((clsag, interim.pseudo_out));
    }
    return None;
  }

  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonce: dfg::EdwardsPoint,
    share: dfg::Scalar,
  ) -> bool {
    let interim = self.interim.as_ref().unwrap();
    return (&share.0 * &ED25519_BASEPOINT_TABLE) == (
      nonce.0 - (interim.p * verification_share.0)
    );
  }
}
