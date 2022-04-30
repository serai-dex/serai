use core::convert::TryInto;

use rand_core::{RngCore, CryptoRng};
use thiserror::Error;

use blake2::{digest::Update, Digest, Blake2b512};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE as DTable,
  traits::VartimeMultiscalarMul,
  scalar::Scalar as DScalar,
  edwards::EdwardsPoint as DPoint
};

use dalek_ff_group::EdwardsPoint;

use ff::PrimeField;
use group::Group;

use dalek_ff_group as dfg;
use frost::{CurveError, Curve};

use crate::random_scalar;

#[derive(Error, Debug)]
pub enum MultisigError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof,
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
    EdwardsPoint(DPoint::vartime_multiscalar_mul(scalars, points))
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

  fn F_from_le_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
    let scalar = Self::F::from_repr(
      slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
    );
    if scalar.is_some().unwrap_u8() == 1 {
      Ok(scalar.unwrap())
    } else {
      Err(CurveError::InvalidScalar)
    }
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let point = dfg::CompressedEdwardsY::new(
      slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
    ).decompress();

    if point.is_some() {
      let point = point.unwrap();
      // Ban torsioned points
      if !point.is_torsion_free() {
        Err(CurveError::InvalidPoint)?
      }
      Ok(point)
    } else {
      Err(CurveError::InvalidPoint)
    }
  }

  fn F_to_le_bytes(f: &Self::F) -> Vec<u8> {
    f.to_repr().to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    g.compress().to_bytes().to_vec()
  }
}

// Used to prove legitimacy in several locations
#[derive(Clone)]
pub struct DLEqProof {
  s: DScalar,
  c: DScalar
}

#[allow(non_snake_case)]
impl DLEqProof {
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &DScalar,
    H: &DPoint,
    alt: &DPoint
  ) -> DLEqProof {
    let r = random_scalar(rng);
    let R1 =  &DTable * &r;
    let R2 = r * H;

    let c = dfg::Scalar::from_hash(
      Blake2b512::new()
        .chain(R1.compress().to_bytes())
        .chain(R2.compress().to_bytes())
        .chain((secret * &DTable).compress().to_bytes())
        .chain(alt.compress().to_bytes())
    ).0;
    let s = r + (c * secret);

    DLEqProof { s, c }
  }

  pub fn verify(
    &self,
    H: &DPoint,
    primary: &DPoint,
    alt: &DPoint
) -> Result<(), MultisigError> {
    let s = self.s;
    let c = self.c;

    let R1 = (&s * &DTable) - (c * primary);
    let R2 = (s * H) - (c * alt);

    let expected_c = dfg::Scalar::from_hash(
      Blake2b512::new()
        .chain(R1.compress().to_bytes())
        .chain(R2.compress().to_bytes())
        .chain(primary.compress().to_bytes())
        .chain(alt.compress().to_bytes())
    ).0;

    // Take the opportunity to ensure a lack of torsion in key images/randomness commitments
    if (!primary.is_torsion_free()) || (!alt.is_torsion_free()) || (c != expected_c) {
      Err(MultisigError::InvalidDLEqProof)?;
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
