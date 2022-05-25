use core::convert::TryInto;

use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use blake2::{digest::Update, Digest, Blake2b512};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE as DTable,
  traits::VartimeMultiscalarMul,
  scalar::Scalar as DScalar,
  edwards::EdwardsPoint as DPoint
};

use ff::PrimeField;
use group::Group;

use transcript::{Transcript as TranscriptTrait, DigestTranscript};
use frost::{CurveError, Curve};
use dalek_ff_group as dfg;

use crate::random_scalar;

pub type Transcript = DigestTranscript::<blake2::Blake2b512>;

#[derive(Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof(u16),
  #[error("invalid key image {0}")]
  InvalidKeyImage(u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519;
impl Curve for Ed25519 {
  type F = dfg::Scalar;
  type G = dfg::EdwardsPoint;
  type T = &'static dfg::EdwardsBasepointTable;

  fn id() -> String {
    "Ed25519".to_string()
  }

  fn id_len() -> u8 {
    Self::id().len() as u8
  }

  fn generator() -> Self::G {
    Self::G::generator()
  }

  fn generator_table() -> Self::T {
    &dfg::ED25519_BASEPOINT_TABLE
  }

  fn multiexp_vartime(scalars: &[Self::F], points: &[Self::G]) -> Self::G {
    dfg::EdwardsPoint(DPoint::vartime_multiscalar_mul(scalars, points))
  }

  // This, as used by CLSAG, will already be a keccak256 hash
  // The only necessity is for this to be unique, which means skipping a hash here should be fine accordingly
  // TODO: Decide
  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    Blake2b512::digest(msg).to_vec()
  }

  fn hash_to_F(data: &[u8]) -> Self::F {
    dfg::Scalar::from_hash(Blake2b512::new().chain(data))
  }

  fn F_len() -> usize {
    32
  }

  fn G_len() -> usize {
    32
  }

  fn F_from_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
    let scalar = Self::F::from_repr(
      slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
    );
    if scalar.is_some().unwrap_u8() == 0 {
      Err(CurveError::InvalidScalar)?;
    }
    Ok(scalar.unwrap())
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let bytes = slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?;
    let point = dfg::CompressedEdwardsY::new(bytes).decompress();

    if let Some(point) = point {
      // Ban torsioned points
      if !point.is_torsion_free() {
        Err(CurveError::InvalidPoint)?;
      }
      // Ban points which weren't canonically encoded
      if point.compress().to_bytes() != bytes {
        Err(CurveError::InvalidPoint)?;
      }
      Ok(point)
    } else {
      Err(CurveError::InvalidPoint)
    }
  }

  fn F_to_bytes(f: &Self::F) -> Vec<u8> {
    f.to_repr().to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    g.compress().to_bytes().to_vec()
  }
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
    let mut transcript = Transcript::new(b"DLEq Proof".to_vec());
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
pub fn read_dleq(
  serialized: &[u8],
  start: usize,
  H: &DPoint,
  l: u16,
  xG: &DPoint
) -> Result<dfg::EdwardsPoint, MultisigError> {
  // Not using G_from_slice here would enable non-canonical points and break blame
  let other = <Ed25519 as Curve>::G_from_slice(
    &serialized[(start + 0) .. (start + 32)]
  ).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  DLEqProof::deserialize(&serialized[(start + 32) .. (start + 96)])
    .ok_or(MultisigError::InvalidDLEqProof(l))?
    .verify(H, l, xG, &other).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  Ok(other)
}
