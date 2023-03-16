#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! A modular implementation of FROST for any curve with a ff/group API.
//! Additionally, custom algorithms may be specified so any signature reducible to
//! Schnorr-like may be used with FROST.
//!
//! A Schnorr algorithm is provided, of the form (R, s) where `s = r + cx`, which
//! allows specifying the challenge format. This is intended to easily allow
//! integrating with existing systems.
//!
//! This library offers ciphersuites compatible with the
//! [IETF draft](https://github.com/cfrg/draft-irtf-cfrg-frost). Currently, version
//! 11 is supported.

use core::fmt::Debug;
use std::collections::HashMap;

use thiserror::Error;

/// Distributed key generation protocol.
pub use dkg::{self, Participant, ThresholdParams, ThresholdCore, ThresholdKeys, ThresholdView};

/// Curve trait and provided curves/HRAMs, forming various ciphersuites.
pub mod curve;
use curve::Curve;

/// Algorithm for the signing process.
pub mod algorithm;
mod nonce;
/// Threshold signing protocol.
pub mod sign;

/// Tests for application-provided curves and algorithms.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// Various errors possible during signing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum FrostError {
  #[error("invalid participant (0 < participant <= {0}, yet participant is {1})")]
  InvalidParticipant(u16, Participant),
  #[error("invalid signing set ({0})")]
  InvalidSigningSet(&'static str),
  #[error("invalid participant quantity (expected {0}, got {1})")]
  InvalidParticipantQuantity(usize, usize),
  #[error("duplicated participant ({0})")]
  DuplicatedParticipant(Participant),
  #[error("missing participant {0}")]
  MissingParticipant(Participant),

  #[error("invalid preprocess (participant {0})")]
  InvalidPreprocess(Participant),
  #[error("invalid share (participant {0})")]
  InvalidShare(Participant),

  #[error("internal error ({0})")]
  InternalError(&'static str),
}

// Validate a map of values to have the expected included participants
pub fn validate_map<T>(
  map: &HashMap<Participant, T>,
  included: &[Participant],
  ours: Participant,
) -> Result<(), FrostError> {
  if (map.len() + 1) != included.len() {
    Err(FrostError::InvalidParticipantQuantity(included.len(), map.len() + 1))?;
  }

  for included in included {
    if *included == ours {
      if map.contains_key(included) {
        Err(FrostError::DuplicatedParticipant(*included))?;
      }
      continue;
    }

    if !map.contains_key(included) {
      Err(FrostError::MissingParticipant(*included))?;
    }
  }

  Ok(())
}
