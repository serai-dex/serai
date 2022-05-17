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

use transcript::DigestTranscript;
use frost::{CurveError, Curve};
use dalek_ff_group as dfg;

use crate::random_scalar;

pub type Transcript = DigestTranscript::<blake2::Blake2b512>;

#[derive(Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof(usize),
  #[error("invalid key image {0}")]
  InvalidKeyImage(usize)
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
      // Ban point which weren't canonically encoded
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
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    H: &DPoint,
    secret: &DScalar
  ) -> DLEqProof {
    let r = random_scalar(rng);
    let rG = &DTable * &r;
    let rH = r * H;

    // TODO: Should this use a transcript?
    let c = dfg::Scalar::from_hash(
      Blake2b512::new()
        // Doesn't include G which is constant, does include H which isn't
        .chain(H.compress().to_bytes())
        .chain((secret * &DTable).compress().to_bytes())
        // We can frequently save a scalar mul if we accept this as an arg, yet it opens room for
        // ambiguity not worth having
        .chain((secret * H).compress().to_bytes())
        .chain(rG.compress().to_bytes())
        .chain(rH.compress().to_bytes())
    ).0;
    let s = r + (c * secret);

    DLEqProof { s, c }
  }

  pub fn verify(
    &self,
    H: &DPoint,
    l: usize,
    sG: &DPoint,
    sH: &DPoint
  ) -> Result<(), MultisigError> {
    let s = self.s;
    let c = self.c;

    let rG = (&s * &DTable) - (c * sG);
    let rH = (s * H) - (c * sH);

    let expected_c = dfg::Scalar::from_hash(
      Blake2b512::new()
        .chain(H.compress().to_bytes())
        .chain(sG.compress().to_bytes())
        .chain(sH.compress().to_bytes())
        .chain(rG.compress().to_bytes())
        .chain(rH.compress().to_bytes())
    ).0;

    // Take the opportunity to ensure a lack of torsion in key images/nonce commitments
    if c != expected_c {
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

    Some(
      DLEqProof {
        s: DScalar::from_bytes_mod_order(serialized[0 .. 32].try_into().unwrap()),
        c: DScalar::from_bytes_mod_order(serialized[32 .. 64].try_into().unwrap())
      }
    )
  }
}

#[allow(non_snake_case)]
pub fn read_dleq(
  serialized: &[u8],
  start: usize,
  H: &DPoint,
  l: usize,
  sG: &DPoint
) -> Result<dfg::EdwardsPoint, MultisigError> {
  // Not using G_from_slice here would enable non-canonical points and break blame
  let other = <Ed25519 as Curve>::G_from_slice(
    &serialized[(start + 0) .. (start + 32)]
  ).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  let proof = DLEqProof::deserialize(
    &serialized[(start + 32) .. (start + 96)]
  ).ok_or(MultisigError::InvalidDLEqProof(l))?;
  proof.verify(
    H,
    l,
    sG,
    &other
  ).map_err(|_| MultisigError::InvalidDLEqProof(l))?;

  Ok(other)
}
