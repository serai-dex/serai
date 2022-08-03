use std::io::Read;

use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use group::{Group, GroupEncoding};

use transcript::{Transcript, RecommendedTranscript};
use dalek_ff_group as dfg;
use dleq::DLEqProof;

#[derive(Clone, Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof(u16),
  #[error("invalid key image {0}")]
  InvalidKeyImage(u16),
}

fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"monero_key_image_dleq")
}

#[allow(non_snake_case)]
pub(crate) fn write_dleq<R: RngCore + CryptoRng>(
  rng: &mut R,
  H: EdwardsPoint,
  mut x: Scalar,
) -> Vec<u8> {
  let mut res = Vec::with_capacity(64);
  DLEqProof::prove(
    rng,
    // Doesn't take in a larger transcript object due to the usage of this
    // Every prover would immediately write their own DLEq proof, when they can only do so in
    // the proper order if they want to reach consensus
    // It'd be a poor API to have CLSAG define a new transcript solely to pass here, just to try to
    // merge later in some form, when it should instead just merge xH (as it does)
    &mut transcript(),
    &[dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(H)],
    dfg::Scalar(x),
  )
  .serialize(&mut res)
  .unwrap();
  x.zeroize();
  res
}

#[allow(non_snake_case)]
pub(crate) fn read_dleq<Re: Read>(
  serialized: &mut Re,
  H: EdwardsPoint,
  l: u16,
  xG: dfg::EdwardsPoint,
) -> Result<dfg::EdwardsPoint, MultisigError> {
  let mut bytes = [0; 32];
  serialized.read_exact(&mut bytes).map_err(|_| MultisigError::InvalidDLEqProof(l))?;
  // dfg ensures the point is torsion free
  let xH = Option::<dfg::EdwardsPoint>::from(dfg::EdwardsPoint::from_bytes(&bytes))
    .ok_or(MultisigError::InvalidDLEqProof(l))?;
  // Ensure this is a canonical point
  if xH.to_bytes() != bytes {
    Err(MultisigError::InvalidDLEqProof(l))?;
  }

  DLEqProof::<dfg::EdwardsPoint>::deserialize(serialized)
    .map_err(|_| MultisigError::InvalidDLEqProof(l))?
    .verify(&mut transcript(), &[dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(H)], &[xG, xH])
    .map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  Ok(xH)
}
