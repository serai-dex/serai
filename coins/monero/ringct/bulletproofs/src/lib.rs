#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};
use zeroize::Zeroizing;

use curve25519_dalek::edwards::EdwardsPoint;

use monero_io::*;
pub use monero_generators::MAX_COMMITMENTS;
use monero_primitives::Commitment;

pub(crate) mod scalar_vector;
pub(crate) mod core;
use crate::core::LOG_COMMITMENT_BITS;

pub(crate) mod batch_verifier;
use batch_verifier::{BulletproofsBatchVerifier, BulletproofsPlusBatchVerifier};
pub use batch_verifier::BatchVerifier;

pub(crate) mod original;
use crate::original::OriginalStruct;

pub(crate) mod plus;
use crate::plus::*;

#[cfg(test)]
mod tests;

/// An error from proving/verifying Bulletproofs(+).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum BulletproofError {
  /// Proving/verifying a Bulletproof(+) range proof with no commitments.
  #[cfg_attr(feature = "std", error("no commitments to prove the range for"))]
  NoCommitments,
  /// Proving/verifying a Bulletproof(+) range proof with more commitments than supported.
  #[cfg_attr(feature = "std", error("too many commitments to prove the range for"))]
  TooManyCommitments,
}

/// A Bulletproof(+).
///
/// This encapsulates either a Bulletproof or a Bulletproof+.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproof {
  /// A Bulletproof.
  Original(OriginalStruct),
  /// A Bulletproof+.
  Plus(AggregateRangeProof),
}

impl Bulletproof {
  fn bp_fields(plus: bool) -> usize {
    if plus {
      6
    } else {
      9
    }
  }

  /// Calculate the weight penalty for the Bulletproof(+).
  ///
  /// Bulletproofs(+) are logarithmically sized yet linearly timed. Evaluating by their size alone
  /// accordingly doesn't properly represent the burden of the proof. Monero 'claws back' some of
  /// the weight lost by using a proof smaller than it is fast to compensate for this.
  // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
  //   src/cryptonote_basic/cryptonote_format_utils.cpp#L106-L124
  pub fn calculate_bp_clawback(plus: bool, n_outputs: usize) -> (usize, usize) {
    #[allow(non_snake_case)]
    let mut LR_len = 0;
    let mut n_padded_outputs = 1;
    while n_padded_outputs < n_outputs {
      LR_len += 1;
      n_padded_outputs = 1 << LR_len;
    }
    LR_len += LOG_COMMITMENT_BITS;

    let mut bp_clawback = 0;
    if n_padded_outputs > 2 {
      let fields = Bulletproof::bp_fields(plus);
      let base = ((fields + (2 * (LOG_COMMITMENT_BITS + 1))) * 32) / 2;
      let size = (fields + (2 * LR_len)) * 32;
      bp_clawback = ((base * n_padded_outputs) - size) * 4 / 5;
    }

    (bp_clawback, LR_len)
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof.
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: &[Commitment],
  ) -> Result<Bulletproof, BulletproofError> {
    if outputs.is_empty() {
      Err(BulletproofError::NoCommitments)?;
    }
    if outputs.len() > MAX_COMMITMENTS {
      Err(BulletproofError::TooManyCommitments)?;
    }
    Ok(Bulletproof::Original(OriginalStruct::prove(rng, outputs)))
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof+.
  pub fn prove_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: Vec<Commitment>,
  ) -> Result<Bulletproof, BulletproofError> {
    if outputs.is_empty() {
      Err(BulletproofError::NoCommitments)?;
    }
    if outputs.len() > MAX_COMMITMENTS {
      Err(BulletproofError::TooManyCommitments)?;
    }
    Ok(Bulletproof::Plus(
      AggregateRangeStatement::new(outputs.iter().map(Commitment::calculate).collect())
        .unwrap()
        .prove(rng, &Zeroizing::new(AggregateRangeWitness::new(outputs).unwrap()))
        .unwrap(),
    ))
  }

  /// Verify the given Bulletproof(+).
  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(&self, rng: &mut R, commitments: &[EdwardsPoint]) -> bool {
    match self {
      Bulletproof::Original(bp) => {
        let mut verifier = BulletproofsBatchVerifier::default();
        if !bp.verify(rng, &mut verifier, commitments) {
          return false;
        }
        verifier.verify()
      }
      Bulletproof::Plus(bp) => {
        let mut verifier = BulletproofsPlusBatchVerifier::default();
        let Some(statement) = AggregateRangeStatement::new(commitments.to_vec()) else {
          return false;
        };
        if !statement.verify(rng, &mut verifier, bp.clone()) {
          return false;
        }
        verifier.verify()
      }
    }
  }

  /// Accumulate the verification for the given Bulletproof(+) into the specified BatchVerifier.
  ///
  /// Returns false if the Bulletproof(+) isn't sane, leaving the BatchVerifier in an undefined
  /// state.
  ///
  /// Returns true if the Bulletproof(+) is sane, regardless of its validity.
  ///
  /// The BatchVerifier must have its verification function executed to actually verify this proof.
  #[must_use]
  pub fn batch_verify<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier,
    commitments: &[EdwardsPoint],
  ) -> bool {
    match self {
      Bulletproof::Original(bp) => bp.verify(rng, &mut verifier.original, commitments),
      Bulletproof::Plus(bp) => {
        let Some(statement) = AggregateRangeStatement::new(commitments.to_vec()) else {
          return false;
        };
        statement.verify(rng, &mut verifier.plus, bp.clone())
      }
    }
  }

  fn write_core<W: Write, F: Fn(&[EdwardsPoint], &mut W) -> io::Result<()>>(
    &self,
    w: &mut W,
    specific_write_vec: F,
  ) -> io::Result<()> {
    match self {
      Bulletproof::Original(bp) => {
        write_point(&bp.A, w)?;
        write_point(&bp.S, w)?;
        write_point(&bp.T1, w)?;
        write_point(&bp.T2, w)?;
        write_scalar(&bp.tau_x, w)?;
        write_scalar(&bp.mu, w)?;
        specific_write_vec(&bp.L, w)?;
        specific_write_vec(&bp.R, w)?;
        write_scalar(&bp.a, w)?;
        write_scalar(&bp.b, w)?;
        write_scalar(&bp.t, w)
      }

      Bulletproof::Plus(bp) => {
        write_point(&bp.A, w)?;
        write_point(&bp.wip.A, w)?;
        write_point(&bp.wip.B, w)?;
        write_scalar(&bp.wip.r_answer, w)?;
        write_scalar(&bp.wip.s_answer, w)?;
        write_scalar(&bp.wip.delta_answer, w)?;
        specific_write_vec(&bp.wip.L, w)?;
        specific_write_vec(&bp.wip.R, w)
      }
    }
  }

  /// Write a Bulletproof(+) for the message signed by a transaction's signature.
  ///
  /// This has a distinct encoding from the standard encoding.
  pub fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_raw_vec(write_point, points, w))
  }

  /// Write a Bulletproof(+).
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_vec(write_point, points, w))
  }

  /// Serialize a Bulletproof(+) to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Read a Bulletproof.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
    Ok(Bulletproof::Original(OriginalStruct {
      A: read_point(r)?,
      S: read_point(r)?,
      T1: read_point(r)?,
      T2: read_point(r)?,
      tau_x: read_scalar(r)?,
      mu: read_scalar(r)?,
      L: read_vec(read_point, r)?,
      R: read_vec(read_point, r)?,
      a: read_scalar(r)?,
      b: read_scalar(r)?,
      t: read_scalar(r)?,
    }))
  }

  /// Read a Bulletproof+.
  pub fn read_plus<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
    Ok(Bulletproof::Plus(AggregateRangeProof {
      A: read_point(r)?,
      wip: WipProof {
        A: read_point(r)?,
        B: read_point(r)?,
        r_answer: read_scalar(r)?,
        s_answer: read_scalar(r)?,
        delta_answer: read_scalar(r)?,
        L: read_vec(read_point, r)?.into_iter().collect(),
        R: read_vec(read_point, r)?.into_iter().collect(),
      },
    }))
  }
}
