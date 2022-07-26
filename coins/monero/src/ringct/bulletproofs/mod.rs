#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::EdwardsPoint;

use crate::{Commitment, wallet::TransactionError, serialize::*};

pub(crate) mod scalar_vector;

mod core;
pub(crate) use self::core::Bulletproofs;
use self::core::{MAX_M, prove};

pub(crate) const MAX_OUTPUTS: usize = MAX_M;

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

  pub fn prove<R: RngCore + CryptoRng>(
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
    match self {
      Bulletproofs::Original { A, S, T1, T2, taux, mu, L, R, a, b, t } => {
        write_point(A, w)?;
        write_point(S, w)?;
        write_point(T1, w)?;
        write_point(T2, w)?;
        write_scalar(taux, w)?;
        write_scalar(mu, w)?;
        specific_write_vec(L, w)?;
        specific_write_vec(R, w)?;
        write_scalar(a, w)?;
        write_scalar(b, w)?;
        write_scalar(t, w)
      }
    }
  }

  pub fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_raw_vec(write_point, points, w))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_vec(write_point, points, w))
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Bulletproofs> {
    Ok(Bulletproofs::Original {
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
    })
  }
}
