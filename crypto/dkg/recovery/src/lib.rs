#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

use core::ops::{Deref as _, DerefMut as _};
extern crate alloc;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use ciphersuite::{GroupIo, Id};

pub use dkg::*;

/// Errors encountered when recovering a secret-shared key from a collection of
/// `dkg::ThresholdKeys`.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RecoveryError {
  /// No keys were provided.
  #[error("no keys provided")]
  NoKeysProvided,
  /// Not enough keys were provided.
  #[error("not enough keys provided (threshold required {required}, provided {provided})")]
  NotEnoughKeysProvided { required: u16, provided: usize },
  /// The keys had inconsistent parameters.
  #[error("keys had inconsistent parameters")]
  InconsistentParameters,
  /// The keys are from distinct secret-sharing sessions or otherwise corrupt.
  #[error("recovery failed")]
  Failure,
  /// An error propagated from the underlying `dkg` crate.
  #[error("error from dkg ({0})")]
  DkgError(DkgError),
}

/// Recover a shared secret from a collection of `dkg::ThresholdKeys`.
pub fn recover_key<C: GroupIo + Id>(
  keys: &[ThresholdKeys<C>],
) -> Result<Zeroizing<C::F>, RecoveryError> {
  let included = keys.iter().map(|keys| keys.params().i()).collect::<Vec<_>>();

  let keys_len = keys.len();
  let mut keys = keys.iter();
  let first_keys = keys.next().ok_or(RecoveryError::NoKeysProvided)?;
  {
    let t = first_keys.params().t();
    if keys_len < usize::from(t) {
      Err(RecoveryError::NotEnoughKeysProvided { required: t, provided: keys_len })?;
    }
  }
  {
    let first_params = (
      first_keys.params().t(),
      first_keys.params().n(),
      first_keys.group_key(),
      first_keys.current_scalar(),
      first_keys.current_offset(),
    );
    for keys in keys.clone() {
      let params = (
        keys.params().t(),
        keys.params().n(),
        keys.group_key(),
        keys.current_scalar(),
        keys.current_offset(),
      );
      if params != first_params {
        Err(RecoveryError::InconsistentParameters)?;
      }
    }
  }

  let mut res: Zeroizing<_> =
    first_keys.view(included.clone()).map_err(RecoveryError::DkgError)?.secret_share().clone();
  for keys in keys {
    *res.deref_mut() +=
      keys.view(included.clone()).map_err(RecoveryError::DkgError)?.secret_share().deref();
  }

  if (C::generator() * res.deref()) != first_keys.group_key() {
    Err(RecoveryError::Failure)?;
  }

  Ok(res)
}
