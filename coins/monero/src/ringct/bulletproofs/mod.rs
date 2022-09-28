#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;
use multiexp::BatchVerifier;

use crate::{Commitment, wallet::TransactionError, serialize::*};

pub(crate) mod scalar_vector;
pub(crate) mod core;
use self::core::LOG_N;

pub(crate) mod original;
pub use original::GENERATORS as BULLETPROOFS_GENERATORS;
pub(crate) mod plus;
pub use plus::GENERATORS as BULLETPROOFS_PLUS_GENERATORS;

pub(crate) use self::original::OriginalStruct;
pub(crate) use self::plus::PlusStruct;

pub(crate) const MAX_OUTPUTS: usize = self::core::MAX_M;

/// Bulletproofs enum, supporting the original and plus formulations.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproofs {
  Original(OriginalStruct),
  Plus(PlusStruct),
}

impl Bulletproofs {
  pub(crate) fn fee_weight(plus: bool, outputs: usize) -> usize {
    let fields = if plus { 6 } else { 9 };

    #[allow(non_snake_case)]
    let mut LR_len = usize::try_from(usize::BITS - (outputs - 1).leading_zeros()).unwrap();
    let padded_outputs = 1 << LR_len;
    LR_len += LOG_N;

    let len = (fields + (2 * LR_len)) * 32;
    len +
      if padded_outputs <= 2 {
        0
      } else {
        let base = ((fields + (2 * (LOG_N + 1))) * 32) / 2;
        let size = (fields + (2 * LR_len)) * 32;
        ((base * padded_outputs) - size) * 4 / 5
      }
  }

  /// Prove the list of commitments are within [0 .. 2^64).
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: &[Commitment],
    plus: bool,
  ) -> Result<Bulletproofs, TransactionError> {
    if outputs.len() > MAX_OUTPUTS {
      return Err(TransactionError::TooManyOutputs)?;
    }
    Ok(if !plus {
      Bulletproofs::Original(OriginalStruct::prove(rng, outputs))
    } else {
      Bulletproofs::Plus(PlusStruct::prove(rng, outputs))
    })
  }

  /// Verify the given Bulletproofs.
  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(&self, rng: &mut R, commitments: &[EdwardsPoint]) -> bool {
    match self {
      Bulletproofs::Original(bp) => bp.verify(rng, commitments),
      Bulletproofs::Plus(bp) => bp.verify(rng, commitments),
    }
  }

  /// Accumulate the verification for the given Bulletproofs into the specified BatchVerifier.
  /// Returns false if the Bulletproofs aren't sane, without mutating the BatchVerifier.
  /// Returns true if the Bulletproofs are sane, regardless of their validity.
  #[must_use]
  pub fn batch_verify<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, dalek_ff_group::EdwardsPoint>,
    id: ID,
    commitments: &[EdwardsPoint],
  ) -> bool {
    match self {
      Bulletproofs::Original(bp) => bp.batch_verify(rng, verifier, id, commitments),
      Bulletproofs::Plus(bp) => bp.batch_verify(rng, verifier, id, commitments),
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

  pub(crate) fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_raw_vec(write_point, points, w))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.serialize_core(w, |points, w| write_vec(write_point, points, w))
  }

  /// Deserialize non-plus Bulletproofs.
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

  /// Deserialize Bulletproofs+.
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
