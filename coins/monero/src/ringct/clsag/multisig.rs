use core::fmt::Debug;
use std::{
  io::{self, Read, Write},
  sync::{Arc, RwLock},
};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::{Identity, IsIdentity},
  scalar::Scalar,
  edwards::EdwardsPoint,
};

use group::{Group, GroupEncoding};

use transcript::{Transcript, RecommendedTranscript};
use dalek_ff_group as dfg;
use dleq::DLEqProof;
use frost::{
  curve::Ed25519,
  FrostError, FrostView,
  algorithm::{AddendumSerialize, Algorithm},
};

use crate::ringct::{
  hash_to_point,
  clsag::{ClsagInput, Clsag},
};

fn dleq_transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"monero_key_image_dleq")
}

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
      ring.extend(pair[0].compress().to_bytes());
      ring.extend(pair[1].compress().to_bytes());
    }
    transcript.append_message(b"ring", &ring);

    // Doesn't include the commitment's parts as the above ring + index includes the commitment
    // The only potential malleability would be if the G/H relationship is known breaking the
    // discrete log problem, which breaks everything already
  }
}

/// CLSAG input and the mask to use for it.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ClsagDetails {
  input: ClsagInput,
  mask: Scalar,
}

impl ClsagDetails {
  pub fn new(input: ClsagInput, mask: Scalar) -> ClsagDetails {
    ClsagDetails { input, mask }
  }
}

/// Addendum produced during the FROST signing process with relevant data.
#[derive(Clone, PartialEq, Eq, Zeroize, Debug)]
pub struct ClsagAddendum {
  pub(crate) key_image: dfg::EdwardsPoint,
  dleq: DLEqProof<dfg::EdwardsPoint>,
}

impl AddendumSerialize for ClsagAddendum {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.key_image.compress().to_bytes().as_ref())?;
    self.dleq.serialize(writer)
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
struct Interim {
  p: Scalar,
  c: Scalar,

  clsag: Clsag,
  pseudo_out: EdwardsPoint,
}

/// FROST algorithm for producing a CLSAG signature.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct ClsagMultisig {
  transcript: RecommendedTranscript,

  H: EdwardsPoint,
  // Merged here as CLSAG needs it, passing it would be a mess, yet having it beforehand requires
  // an extra round
  image: EdwardsPoint,

  details: Arc<RwLock<Option<ClsagDetails>>>,

  msg: Option<[u8; 32]>,
  interim: Option<Interim>,
}

impl ClsagMultisig {
  pub fn new(
    transcript: RecommendedTranscript,
    output_key: EdwardsPoint,
    details: Arc<RwLock<Option<ClsagDetails>>>,
  ) -> ClsagMultisig {
    ClsagMultisig {
      transcript,

      H: hash_to_point(output_key),
      image: EdwardsPoint::identity(),

      details,

      msg: None,
      interim: None,
    }
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
  type Addendum = ClsagAddendum;
  type Signature = (Clsag, EdwardsPoint);

  fn nonces(&self) -> Vec<Vec<dfg::EdwardsPoint>> {
    vec![vec![dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(self.H)]]
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    view: &FrostView<Ed25519>,
  ) -> ClsagAddendum {
    ClsagAddendum {
      key_image: dfg::EdwardsPoint(self.H * view.secret_share().0),
      dleq: DLEqProof::prove(
        rng,
        // Doesn't take in a larger transcript object due to the usage of this
        // Every prover would immediately write their own DLEq proof, when they can only do so in
        // the proper order if they want to reach consensus
        // It'd be a poor API to have CLSAG define a new transcript solely to pass here, just to
        // try to merge later in some form, when it should instead just merge xH (as it does)
        &mut dleq_transcript(),
        &[dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(self.H)],
        dfg::Scalar(view.secret_share().0),
      ),
    }
  }

  fn read_addendum<R: Read>(&self, reader: &mut R) -> io::Result<ClsagAddendum> {
    let mut bytes = [0; 32];
    reader.read_exact(&mut bytes)?;
    // dfg ensures the point is torsion free
    let xH = Option::<dfg::EdwardsPoint>::from(dfg::EdwardsPoint::from_bytes(&bytes))
      .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid key image"))?;
    // Ensure this is a canonical point
    if xH.to_bytes() != bytes {
      Err(io::Error::new(io::ErrorKind::Other, "non-canonical key image"))?;
    }

    Ok(ClsagAddendum { key_image: xH, dleq: DLEqProof::<dfg::EdwardsPoint>::deserialize(reader)? })
  }

  fn process_addendum(
    &mut self,
    view: &FrostView<Ed25519>,
    l: u16,
    addendum: ClsagAddendum,
  ) -> Result<(), FrostError> {
    if self.image.is_identity() {
      self.transcript.domain_separate(b"CLSAG");
      self.input().transcript(&mut self.transcript);
      self.transcript.append_message(b"mask", &self.mask().to_bytes());
    }

    self.transcript.append_message(b"participant", &l.to_be_bytes());

    addendum
      .dleq
      .verify(
        &mut dleq_transcript(),
        &[dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(self.H)],
        &[view.verification_share(l), addendum.key_image],
      )
      .map_err(|_| FrostError::InvalidPreprocess(l))?;

    self
      .transcript
      .append_message(b"key_image_share", addendum.key_image.compress().to_bytes().as_ref());
    self.image += addendum.key_image.0;

    Ok(())
  }

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn sign_share(
    &mut self,
    view: &FrostView<Ed25519>,
    nonce_sums: &[Vec<dfg::EdwardsPoint>],
    nonces: &[dfg::Scalar],
    msg: &[u8],
  ) -> dfg::Scalar {
    // Use the transcript to get a seeded random number generator
    // The transcript contains private data, preventing passive adversaries from recreating this
    // process even if they have access to commitments (specifically, the ring index being signed
    // for, along with the mask which should not only require knowing the shared keys yet also the
    // input commitment masks)
    let mut rng = ChaCha20Rng::from_seed(self.transcript.rng_seed(b"decoy_responses"));

    self.msg = Some(msg.try_into().expect("CLSAG message should be 32-bytes"));

    #[allow(non_snake_case)]
    let (clsag, pseudo_out, p, c) = Clsag::sign_core(
      &mut rng,
      &self.image,
      &self.input(),
      self.mask(),
      self.msg.as_ref().unwrap(),
      nonce_sums[0][0].0,
      nonce_sums[0][1].0,
    );
    self.interim = Some(Interim { p, c, clsag, pseudo_out });

    nonces[0] - (dfg::Scalar(p) * view.secret_share())
  }

  #[must_use]
  fn verify(
    &self,
    _: dfg::EdwardsPoint,
    _: &[Vec<dfg::EdwardsPoint>],
    sum: dfg::Scalar,
  ) -> Option<Self::Signature> {
    let interim = self.interim.as_ref().unwrap();
    let mut clsag = interim.clsag.clone();
    clsag.s[usize::from(self.input().decoys.i)] = sum.0 - interim.c;
    if clsag
      .verify(
        &self.input().decoys.ring,
        &self.image,
        &interim.pseudo_out,
        self.msg.as_ref().unwrap(),
      )
      .is_ok()
    {
      return Some((clsag, interim.pseudo_out));
    }
    None
  }

  #[must_use]
  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonces: &[Vec<dfg::EdwardsPoint>],
    share: dfg::Scalar,
  ) -> bool {
    let interim = self.interim.as_ref().unwrap();
    (&share.0 * &ED25519_BASEPOINT_TABLE) == (nonces[0][0].0 - (interim.p * verification_share.0))
  }
}
