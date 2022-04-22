use core::convert::TryInto;

use group::{Group, GroupEncoding};

use jubjub::{Fr, SubgroupPoint};
use frost::{CurveError, Curve, multiexp_vartime};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Jubjub;
impl Curve for Jubjub {
  type F = Fr;
  type G = SubgroupPoint;
  type T = SubgroupPoint;

  fn id() -> String {
    "Jubjub".to_string()
  }

  fn id_len() -> u8 {
    Self::id().len() as u8
  }

  fn generator() -> Self::G {
    Self::G::generator()
  }

  fn generator_table() -> Self::T {
    Self::G::generator()
  }

  fn multiexp_vartime(scalars: &[Self::F], points: &[Self::G]) -> Self::G {
    multiexp_vartime::<Jubjub>(scalars, points)
  }

  fn F_len() -> usize {
    32
  }

  fn G_len() -> usize {
    32
  }

  fn F_from_le_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
    let scalar = Self::F::from_bytes(
      &slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
    );
    if scalar.is_some().into() {
      Ok(scalar.unwrap())
    } else {
      Err(CurveError::InvalidScalar(hex::encode(slice)))
    }
  }

  fn F_from_le_slice_unreduced(slice: &[u8]) -> Self::F {
    let mut wide: [u8; 64] = [0; 64];
    wide[..slice.len()].copy_from_slice(slice);
    Self::F::from_bytes_wide(&wide)
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let point = Self::G::from_bytes(
      &slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
    );
    if point.is_some().into() {
      Ok(point.unwrap())
    } else {
      Err(CurveError::InvalidPoint(hex::encode(slice)))?
    }
  }

  fn F_to_le_bytes(f: &Self::F) -> Vec<u8> {
    f.to_bytes().to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    g.to_bytes().to_vec()
  }

  fn F_from_bytes_wide(bytes: [u8; 64]) -> Self::F {
    Self::F::from_bytes_wide(&bytes)
  }
}
