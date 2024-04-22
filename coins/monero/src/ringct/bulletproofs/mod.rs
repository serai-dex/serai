#![allow(non_snake_case)]

use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::edwards::EdwardsPoint;
use multiexp::BatchVerifier;

use crate::{Commitment, wallet::TransactionError, serialize::*};

pub(crate) mod scalar_vector;
pub(crate) mod core;
use self::core::LOG_N;

pub(crate) mod original;
use self::original::OriginalStruct;

pub(crate) mod plus;
use self::plus::*;

pub(crate) const MAX_OUTPUTS: usize = self::core::MAX_M;

/// Bulletproof enum, encapsulating both Bulletproofs and Bulletproofs+.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproof {
  Original(OriginalStruct),
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

  // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
  //   src/cryptonote_basic/cryptonote_format_utils.cpp#L106-L124
  pub(crate) fn calculate_bp_clawback(plus: bool, n_outputs: usize) -> (usize, usize) {
    #[allow(non_snake_case)]
    let mut LR_len = 0;
    let mut n_padded_outputs = 1;
    while n_padded_outputs < n_outputs {
      LR_len += 1;
      n_padded_outputs = 1 << LR_len;
    }
    LR_len += LOG_N;

    let mut bp_clawback = 0;
    if n_padded_outputs > 2 {
      let fields = Bulletproof::bp_fields(plus);
      let base = ((fields + (2 * (LOG_N + 1))) * 32) / 2;
      let size = (fields + (2 * LR_len)) * 32;
      bp_clawback = ((base * n_padded_outputs) - size) * 4 / 5;
    }

    (bp_clawback, LR_len)
  }

  pub(crate) fn fee_weight(plus: bool, outputs: usize) -> usize {
    #[allow(non_snake_case)]
    let (bp_clawback, LR_len) = Bulletproof::calculate_bp_clawback(plus, outputs);
    32 * (Bulletproof::bp_fields(plus) + (2 * LR_len)) + 2 + bp_clawback
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof.
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: &[Commitment],
  ) -> Result<Bulletproof, TransactionError> {
    if outputs.is_empty() {
      Err(TransactionError::NoOutputs)?;
    }
    if outputs.len() > MAX_OUTPUTS {
      Err(TransactionError::TooManyOutputs)?;
    }
    Ok(Bulletproof::Original(OriginalStruct::prove(rng, outputs)))
  }

  /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof+.
  pub fn prove_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    outputs: Vec<Commitment>,
  ) -> Result<Bulletproof, TransactionError> {
    if outputs.is_empty() {
      Err(TransactionError::NoOutputs)?;
    }
    if outputs.len() > MAX_OUTPUTS {
      Err(TransactionError::TooManyOutputs)?;
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
      Bulletproof::Original(bp) => bp.verify(rng, commitments),
      Bulletproof::Plus(bp) => {
        let mut verifier = BatchVerifier::new(1);
        let Some(statement) = AggregateRangeStatement::new(commitments.to_vec()) else {
          return false;
        };
        if !statement.verify(rng, &mut verifier, (), bp.clone()) {
          return false;
        }
        verifier.verify_vartime()
      }
    }
  }

  /// Accumulate the verification for the given Bulletproof into the specified BatchVerifier.
  ///
  /// Returns false if the Bulletproof isn't sane, leaving the BatchVerifier in an undefined
  /// state.
  /// Returns true if the Bulletproof is sane, regardless of their validity.
  #[must_use]
  pub fn batch_verify<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, dalek_ff_group::EdwardsPoint>,
    id: ID,
    commitments: &[EdwardsPoint],
  ) -> bool {
    match self {
      Bulletproof::Original(bp) => bp.batch_verify(rng, verifier, id, commitments),
      Bulletproof::Plus(bp) => {
        let Some(statement) = AggregateRangeStatement::new(commitments.to_vec()) else {
          return false;
        };
        statement.verify(rng, verifier, id, bp.clone())
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
        write_scalar(&bp.taux, w)?;
        write_scalar(&bp.mu, w)?;
        specific_write_vec(&bp.L, w)?;
        specific_write_vec(&bp.R, w)?;
        write_scalar(&bp.a, w)?;
        write_scalar(&bp.b, w)?;
        write_scalar(&bp.t, w)
      }

      Bulletproof::Plus(bp) => {
        write_point(&bp.A.0, w)?;
        write_point(&bp.wip.A.0, w)?;
        write_point(&bp.wip.B.0, w)?;
        write_scalar(&bp.wip.r_answer.0, w)?;
        write_scalar(&bp.wip.s_answer.0, w)?;
        write_scalar(&bp.wip.delta_answer.0, w)?;
        specific_write_vec(&bp.wip.L.iter().copied().map(|L| L.0).collect::<Vec<_>>(), w)?;
        specific_write_vec(&bp.wip.R.iter().copied().map(|R| R.0).collect::<Vec<_>>(), w)
      }
    }
  }

  pub(crate) fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_raw_vec(write_point, points, w))
  }

  /// Write the Bulletproof(+) to a writer.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.write_core(w, |points, w| write_vec(write_point, points, w))
  }

  /// Serialize the Bulletproof(+) to a `Vec<u8>`.
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
      taux: read_scalar(r)?,
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
    use dalek_ff_group::{Scalar as DfgScalar, EdwardsPoint as DfgPoint};

    Ok(Bulletproof::Plus(AggregateRangeProof {
      A: DfgPoint(read_point(r)?),
      wip: WipProof {
        A: DfgPoint(read_point(r)?),
        B: DfgPoint(read_point(r)?),
        r_answer: DfgScalar(read_scalar(r)?),
        s_answer: DfgScalar(read_scalar(r)?),
        delta_answer: DfgScalar(read_scalar(r)?),
        L: read_vec(read_point, r)?.into_iter().map(DfgPoint).collect(),
        R: read_vec(read_point, r)?.into_iter().map(DfgPoint).collect(),
      },
    }))
  }
}
