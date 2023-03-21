#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

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
}

/// Validate a map of values to have the expected participants.
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
