use core::convert::TryInto;

use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use group::GroupEncoding;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE as DTable,
  scalar::Scalar as DScalar,
  edwards::EdwardsPoint as DPoint
};

use transcript::{Transcript, RecommendedTranscript};
use dalek_ff_group as dfg;

use crate::random_scalar;

#[derive(Clone, Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof(u16),
  #[error("invalid key image {0}")]
  InvalidKeyImage(u16)
}

// Used to prove legitimacy of key images and nonces which both involve other basepoints
#[derive(Clone)]
pub struct DLEqProof {
  s: DScalar,
  c: DScalar
}

#[allow(non_snake_case)]
impl DLEqProof {
  fn challenge(H: &DPoint, xG: &DPoint, xH: &DPoint, rG: &DPoint, rH: &DPoint) -> DScalar {
    // Doesn't take in a larger transcript object due to the usage of this
    // Every prover would immediately write their own DLEq proof, when they can only do so in
    // the proper order if they want to reach consensus
    // It'd be a poor API to have CLSAG define a new transcript solely to pass here, just to try to
    // merge later in some form, when it should instead just merge xH (as it does)
    let mut transcript = RecommendedTranscript::new(b"DLEq Proof");
    // Bit redundant, keeps things consistent
    transcript.domain_separate(b"DLEq");
    // Doesn't include G which is constant, does include H which isn't, even though H manipulation
    // shouldn't be possible in practice as it's independently calculated as a product of known data
    transcript.append_message(b"H", &H.compress().to_bytes());
    transcript.append_message(b"xG", &xG.compress().to_bytes());
    transcript.append_message(b"xH", &xH.compress().to_bytes());
    transcript.append_message(b"rG", &rG.compress().to_bytes());
    transcript.append_message(b"rH", &rH.compress().to_bytes());
    DScalar::from_bytes_mod_order_wide(
      &transcript.challenge(b"challenge").try_into().expect("Blake2b512 output wasn't 64 bytes")
    )
  }

  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    H: &DPoint,
    secret: &DScalar
  ) -> DLEqProof {
    let r = random_scalar(rng);
    let rG = &DTable * &r;
    let rH = r * H;

    // We can frequently (always?) save a scalar mul if we accept xH as an arg, yet it opens room
    // for incorrect data to be passed, and therefore faults, making it not worth having
    // We could also return xH but... it's really micro-optimizing
    let c = DLEqProof::challenge(H, &(secret * &DTable), &(secret * H), &rG, &rH);
    let s = r + (c * secret);

    DLEqProof { s, c }
  }

  pub fn verify(
    &self,
    H: &DPoint,
    l: u16,
    xG: &DPoint,
    xH: &DPoint
  ) -> Result<(), MultisigError> {
    let s = self.s;
    let c = self.c;

    let rG = (&s * &DTable) - (c * xG);
    let rH = (s * H) - (c * xH);

    if c != DLEqProof::challenge(H, &xG, &xH, &rG, &rH) {
      Err(MultisigError::InvalidDLEqProof(l))?;
    }

    Ok(())
  }

  pub fn serialize(
    &self
  ) -> Vec<u8> {
    let mut res = Vec::with_capacity(64);
    res.extend(self.s.to_bytes());
    res.extend(self.c.to_bytes());
    res
  }

  pub fn deserialize(
    serialized: &[u8]
  ) -> Option<DLEqProof> {
    if serialized.len() != 64 {
      return None;
    }

    DScalar::from_canonical_bytes(serialized[0 .. 32].try_into().unwrap()).and_then(
      |s| DScalar::from_canonical_bytes(serialized[32 .. 64].try_into().unwrap()).and_then(
        |c| Some(DLEqProof { s, c })
      )
    )
  }
}

#[allow(non_snake_case)]
pub(crate) fn read_dleq(
  serialized: &[u8],
  start: usize,
  H: &DPoint,
  l: u16,
  xG: &DPoint
) -> Result<dfg::EdwardsPoint, MultisigError> {
  if serialized.len() < start + 96 {
    Err(MultisigError::InvalidDLEqProof(l))?;
  }

  let bytes = (&serialized[(start + 0) .. (start + 32)]).try_into().unwrap();
  // dfg ensures the point is torsion free
  let other = Option::<dfg::EdwardsPoint>::from(
    dfg::EdwardsPoint::from_bytes(&bytes)).ok_or(MultisigError::InvalidDLEqProof(l)
  )?;
  // Ensure this is a canonical point
  if other.to_bytes() != bytes {
    Err(MultisigError::InvalidDLEqProof(l))?;
  }

  DLEqProof::deserialize(&serialized[(start + 32) .. (start + 96)])
    .ok_or(MultisigError::InvalidDLEqProof(l))?
    .verify(H, l, xG, &other).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  Ok(other)
}
