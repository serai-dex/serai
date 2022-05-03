use core::fmt::Debug;
use std::{rc::Rc, cell::RefCell};

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::Identity,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use monero::util::ringct::{Key, Clsag};

use group::Group;

use dalek_ff_group as dfg;
use transcript::Transcript as TranscriptTrait;
use frost::{Curve, FrostError, algorithm::Algorithm, MultisigView};

use crate::{
  Transcript,
  hash_to_point,
  frost::{MultisigError, Ed25519, DLEqProof},
  key_image,
  clsag::{Input, sign_core, verify}
};

impl Input {
  pub fn transcript<T: TranscriptTrait>(&self, transcript: &mut T) {
    // Ring index
    transcript.append_message(b"ring_index", &[self.i]);

    // Ring
    let mut ring = vec![];
    for pair in &self.ring {
      // Doesn't include global output indexes as CLSAG doesn't care and won't be affected by it
      // They're just a mutable reference to this data
      ring.extend(&pair[0].compress().to_bytes());
      ring.extend(&pair[1].compress().to_bytes());
    }
    transcript.append_message(b"ring", &ring);

    // Doesn't include the commitment's parts as the above ring + index includes the commitment
    // The only potential malleability would be if the G/H relationship is known breaking the
    // discrete log problem, which breaks everything already
  }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
struct ClsagSignInterim {
  c: Scalar,
  s: Scalar,

  clsag: Clsag,
  C_out: EdwardsPoint
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Multisig {
  commitments_H: Vec<u8>,
  image: EdwardsPoint,
  AH: (dfg::EdwardsPoint, dfg::EdwardsPoint),

  input: Input,

  msg: Rc<RefCell<[u8; 32]>>,
  mask: Rc<RefCell<Scalar>>,

  interim: Option<ClsagSignInterim>
}

impl Multisig {
  pub fn new(
    input: Input,
    msg: Rc<RefCell<[u8; 32]>>,
    mask: Rc<RefCell<Scalar>>,
  ) -> Result<Multisig, MultisigError> {
    Ok(
      Multisig {
        commitments_H: vec![],
        image: EdwardsPoint::identity(),
        AH: (dfg::EdwardsPoint::identity(), dfg::EdwardsPoint::identity()),

        input,

        msg,
        mask,

        interim: None
      }
    )
  }

  pub fn serialized_len() -> usize {
    3 * (32 + 64)
  }
}

impl Algorithm<Ed25519> for Multisig {
  type Transcript = Transcript;
  type Signature = (Clsag, EdwardsPoint);

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &MultisigView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    let (share, proof) = key_image::generate_share(rng, view);

    #[allow(non_snake_case)]
    let H = hash_to_point(&view.group_key().0);
    #[allow(non_snake_case)]
    let nH = (nonces[0].0 * H, nonces[1].0 * H);

    let mut serialized = Vec::with_capacity(Multisig::serialized_len());
    serialized.extend(share.compress().to_bytes());
    serialized.extend(nH.0.compress().to_bytes());
    serialized.extend(nH.1.compress().to_bytes());
    serialized.extend(&DLEqProof::prove(rng, &nonces[0].0, &H, &nH.0).serialize());
    serialized.extend(&DLEqProof::prove(rng, &nonces[1].0, &H, &nH.1).serialize());
    serialized.extend(proof);
    serialized
  }

  fn process_addendum(
    &mut self,
    view: &MultisigView<Ed25519>,
    l: usize,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    if serialized.len() != Multisig::serialized_len() {
      // Not an optimal error but...
      Err(FrostError::InvalidCommitmentQuantity(l, 9, serialized.len() / 32))?;
    }

    let (share, serialized) = key_image::verify_share(view, l, serialized).map_err(|_| FrostError::InvalidShare(l))?;
    self.image += share;

    let alt = &hash_to_point(&self.input.ring[usize::from(self.input.i)][0]);

    // Uses the same format FROST does for the expected commitments (nonce * G where this is nonce * H)
    self.commitments_H.extend(&u64::try_from(l).unwrap().to_le_bytes());
    self.commitments_H.extend(&serialized[0 .. 64]);

    #[allow(non_snake_case)]
    let H = (
      <Ed25519 as Curve>::G_from_slice(&serialized[0 .. 32]).map_err(|_| FrostError::InvalidCommitment(l))?,
      <Ed25519 as Curve>::G_from_slice(&serialized[32 .. 64]).map_err(|_| FrostError::InvalidCommitment(l))?
    );

    DLEqProof::deserialize(&serialized[64 .. 128]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[0],
      &H.0
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    DLEqProof::deserialize(&serialized[128 .. 192]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[1],
      &H.1
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    self.AH.0 += H.0;
    self.AH.1 += H.1;

    Ok(())
  }

  fn transcript(&self) -> Option<Self::Transcript> {
    let mut transcript = Self::Transcript::new(b"CLSAG");
    self.input.transcript(&mut transcript);
    // Given the fact there's only ever one possible value for this, this may technically not need
    // to be committed to. If signing a TX, it's be double committed to thanks to the message
    // It doesn't hurt to have though and ensures security boundaries are well formed
    transcript.append_message(b"image", &self.image.compress().to_bytes());
    // Given this is guaranteed to match commitments, which FROST commits to, this also technically
    // doesn't need to be committed to if a canonical serialization is guaranteed
    // It, again, doesn't hurt to include and ensures security boundaries are well formed
    transcript.append_message(b"commitments_H", &self.commitments_H);
    transcript.append_message(b"message", &*self.msg.borrow());
    transcript.append_message(b"mask", &self.mask.borrow().to_bytes());
    Some(transcript)
  }

  fn sign_share(
    &mut self,
    view: &MultisigView<Ed25519>,
    nonce_sum: dfg::EdwardsPoint,
    b: dfg::Scalar,
    nonce: dfg::Scalar,
    _: &[u8]
  ) -> dfg::Scalar {
    // Apply the binding factor to the H variant of the nonce
    self.AH.0 += self.AH.1 * b;

    // Use the transcript to get a seeded random number generator
    // The transcript contains private data, preventing passive adversaries from recreating this
    // process even if they have access to commitments (specifically, the ring index being signed
    // for, along with the mask which should not only require knowing the shared keys yet also the
    // input commitment mask)
    let mut rng = self.transcript().unwrap().seeded_rng(b"decoy_responses", None);

    #[allow(non_snake_case)]
    let (clsag, c, mu_C, z, mu_P, C_out) = sign_core(
      &mut rng,
      &self.msg.borrow(),
      &self.input,
      &self.image,
      *self.mask.borrow(),
      nonce_sum.0,
      self.AH.0.0
    );
    self.interim = Some(ClsagSignInterim { c: c * mu_P, s: c * mu_C * z, clsag, C_out });

    let share = dfg::Scalar(nonce.0 - (c * mu_P * view.secret_share().0));

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
    clsag.s[usize::from(self.input.i)] = Key { key: (sum.0 - interim.s).to_bytes() };
    if verify(&clsag, &self.msg.borrow(), self.image, &self.input.ring, interim.C_out) {
      return Some((clsag, interim.C_out));
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
      nonce.0 - (interim.c * verification_share.0)
    );
  }
}
