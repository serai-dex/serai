use std::{convert::TryInto, io::Cursor};

use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use group::{Group, GroupEncoding};

use transcript::RecommendedTranscript;
use dalek_ff_group as dfg;
use dleq::{Generators, DLEqProof};

#[derive(Clone, Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof(u16),
  #[error("invalid key image {0}")]
  InvalidKeyImage(u16)
}

#[allow(non_snake_case)]
pub(crate) fn write_dleq<R: RngCore + CryptoRng>(
  rng: &mut R,
  H: EdwardsPoint,
  x: Scalar
) -> Vec<u8> {
  let mut res = Vec::with_capacity(64);
  DLEqProof::prove(
    rng,
    // Doesn't take in a larger transcript object due to the usage of this
    // Every prover would immediately write their own DLEq proof, when they can only do so in
    // the proper order if they want to reach consensus
    // It'd be a poor API to have CLSAG define a new transcript solely to pass here, just to try to
    // merge later in some form, when it should instead just merge xH (as it does)
    &mut RecommendedTranscript::new(b"DLEq Proof"),
    Generators::new(dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(H)),
    dfg::Scalar(x)
  ).serialize(&mut res).unwrap();
  res
}

#[allow(non_snake_case)]
pub(crate) fn read_dleq(
  serialized: &[u8],
  start: usize,
  H: EdwardsPoint,
  l: u16,
  xG: dfg::EdwardsPoint
) -> Result<dfg::EdwardsPoint, MultisigError> {
  if serialized.len() < start + 96 {
    Err(MultisigError::InvalidDLEqProof(l))?;
  }

  let bytes = (&serialized[(start + 0) .. (start + 32)]).try_into().unwrap();
  // dfg ensures the point is torsion free
  let xH = Option::<dfg::EdwardsPoint>::from(
    dfg::EdwardsPoint::from_bytes(&bytes)).ok_or(MultisigError::InvalidDLEqProof(l)
  )?;
  // Ensure this is a canonical point
  if xH.to_bytes() != bytes {
    Err(MultisigError::InvalidDLEqProof(l))?;
  }

  let proof = DLEqProof::<dfg::EdwardsPoint>::deserialize(
    &mut Cursor::new(&serialized[(start + 32) .. (start + 96)])
  ).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  let mut transcript = RecommendedTranscript::new(b"DLEq Proof");
  proof.verify(&mut transcript, Generators::new(dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(H)), (xG, xH))
    .map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  Ok(xH)
}
