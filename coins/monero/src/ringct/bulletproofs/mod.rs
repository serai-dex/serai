#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use crate::{Commitment, wallet::TransactionError, serialize::*};

pub(crate) mod scalar_vector;

mod core;
pub(crate) use self::core::MAX_M;
use self::core::prove;

pub(crate) const MAX_OUTPUTS: usize = MAX_M;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bulletproofs {
  pub A: EdwardsPoint,
  pub S: EdwardsPoint,
  pub T1: EdwardsPoint,
  pub T2: EdwardsPoint,
  pub taux: Scalar,
  pub mu: Scalar,
  pub L: Vec<EdwardsPoint>,
  pub R: Vec<EdwardsPoint>,
  pub a: Scalar,
  pub b: Scalar,
  pub t: Scalar,
}

impl Bulletproofs {
  pub(crate) fn fee_weight(outputs: usize) -> usize {
    let proofs = 6 + usize::try_from(usize::BITS - (outputs - 1).leading_zeros()).unwrap();
    let len = (9 + (2 * proofs)) * 32;

    let mut clawback = 0;
    let padded = 1 << (proofs - 6);
    if padded > 2 {
      const BP_BASE: usize = 368;
      clawback = ((BP_BASE * padded) - len) * 4 / 5;
    }

    len + clawback
  }

  pub fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: &[Commitment],
  ) -> Result<Bulletproofs, TransactionError> {
    if outputs.len() > MAX_OUTPUTS {
      return Err(TransactionError::TooManyOutputs)?;
    }
    Ok(prove(rng, outputs))
  }

  fn serialize_core<W: std::io::Write, F: Fn(&[EdwardsPoint], &mut W) -> std::io::Result<()>>(
    &self,
    w: &mut W,
    specific_write_vec: F,
  ) -> std::io::Result<()> {
    write_point(&self.A, w)?;
    write_point(&self.S, w)?;
    write_point(&self.T1, w)?;
    write_point(&self.T2, w)?;
    write_scalar(&self.taux, w)?;
    write_scalar(&self.mu, w)?;
    specific_write_vec(&self.L, w)?;
    specific_write_vec(&self.R, w)?;
    write_scalar(&self.a, w)?;
    write_scalar(&self.b, w)?;
    write_scalar(&self.t, w)
  }

  pub fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_raw_vec(write_point, points, w))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_vec(write_point, points, w))
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Bulletproofs> {
    let bp = Bulletproofs {
      A: read_point(r)?,
      S: read_point(r)?,
      T1: read_point(r)?,
      T2: read_point(r)?,
      taux: read_scalar(r)?,
      mu: read_scalar(r)?,
      L: read_vec(read_point, r)?,
      R: read_vec(read_point, r)?,
      a: read_scalar(r)?,
      b: read_scalar(r)?,
      t: read_scalar(r)?,
    };

    if bp.L.len() != bp.R.len() {
      Err(std::io::Error::new(std::io::ErrorKind::Other, "mismatched L/R len"))?;
    }
    Ok(bp)
  }
}
