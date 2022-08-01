#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::EdwardsPoint;
use multiexp::BatchVerifier;

use crate::{Commitment, wallet::TransactionError, serialize::*};

pub(crate) mod scalar_vector;

pub mod core;
pub(crate) use self::core::Bulletproofs;
use self::core::{MAX_M, OriginalStruct, PlusStruct, prove, prove_plus};

pub(crate) const MAX_OUTPUTS: usize = MAX_M;

impl Bulletproofs {
  // TODO
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
    plus: bool,
  ) -> Result<Bulletproofs, TransactionError> {
    if outputs.len() > MAX_OUTPUTS {
      return Err(TransactionError::TooManyOutputs)?;
    }
    Ok(if !plus { prove(rng, outputs) } else { prove_plus(rng, outputs) })
  }

  #[must_use]
  pub fn verify(&self, commitments: &[EdwardsPoint]) -> bool {
    match self {
      Bulletproofs::Original(bp) => bp.verify(commitments),
      Bulletproofs::Plus(_) => unimplemented!("Bulletproofs+ verification isn't implemented"),
    }
  }

  #[must_use]
  pub fn batch_verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<usize, dalek_ff_group::EdwardsPoint>,
    id: usize,
    commitments: &[EdwardsPoint],
  ) -> bool {
    match self {
      Bulletproofs::Original(bp) => bp.batch_verify(rng, verifier, id, commitments),
      Bulletproofs::Plus(_) => unimplemented!("Bulletproofs+ verification isn't implemented"),
    }
  }

  fn serialize_core<W: std::io::Write, F: Fn(&[EdwardsPoint], &mut W) -> std::io::Result<()>>(
    &self,
    w: &mut W,
    specific_write_vec: F,
  ) -> std::io::Result<()> {
    match self {
      Bulletproofs::Original(bp) => {
        write_point(&bp.A, w)?;
        write_point(&bp.S, w)?;
        write_point(&bp.T1, w)?;
        write_point(&bp.T2, w)?;
        write_scalar(&bp.taux, w)?;
        write_scalar(&bp.mu, w)?;
        specific_write_vec(&bp.L, w)?;
        specific_write_vec(&bp.R, w)?;
        write_scalar(&bp.a, w)?;
        write_scalar(&bp.b, w)?;
        write_scalar(&bp.t, w)
      }

      Bulletproofs::Plus(bp) => {
        write_point(&bp.A, w)?;
        write_point(&bp.A1, w)?;
        write_point(&bp.B, w)?;
        write_scalar(&bp.r1, w)?;
        write_scalar(&bp.s1, w)?;
        write_scalar(&bp.d1, w)?;
        specific_write_vec(&bp.L, w)?;
        specific_write_vec(&bp.R, w)
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
    Ok(Bulletproofs::Original(OriginalStruct {
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
    }))
  }

  pub fn deserialize_plus<R: std::io::Read>(r: &mut R) -> std::io::Result<Bulletproofs> {
    Ok(Bulletproofs::Plus(PlusStruct {
      A: read_point(r)?,
      A1: read_point(r)?,
      B: read_point(r)?,
      r1: read_scalar(r)?,
      s1: read_scalar(r)?,
      d1: read_scalar(r)?,
      L: read_vec(read_point, r)?,
      R: read_vec(read_point, r)?,
    }))
  }
}
