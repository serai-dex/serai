#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::ops::Deref as _;
use std_shims::{
  vec,
  vec::Vec,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;

#[rustfmt::skip]
use ciphersuite::{digest::Digest as _, group::GroupEncoding as _, FromUniformBytes as _, Ciphersuite};

pub use dkg::*;

#[cfg(test)]
mod tests;

/// Errors encountered when calculating a MuSig-aggregated key.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum MusigKeyError<C: Ciphersuite> {
  /// No keys were provided.
  #[error("no keys provided")]
  NoKeysProvided,
  /// Too many keys were provided.
  #[error("too many keys (allowed {max}, provided {provided})")]
  TooManyKeysProvided {
    /// The maximum amount of keys allowed.
    max: u16,
    /// The amount of keys provided.
    provided: usize,
  },
  /// A participant was duplicated.
  #[error("a participant was duplicated")]
  DuplicatedParticipant(C::G),
}

/// Errors encountered when working with threshold keys.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum MusigError<C: Ciphersuite> {
  /// An error with regard to the validity of the key which would be made.
  #[error("error with what would be the MuSig key ({0})")]
  MusigKeyError(MusigKeyError<C>),
  /// Participating, yet our public key wasn't found in the list of keys.
  #[error("private key's public key wasn't present in the list of public keys")]
  NotPresent,
  /// An error propagated from the underlying `dkg` crate.
  #[error("error from dkg ({0})")]
  DkgError(DkgError),
}

fn check_keys<C: Ciphersuite>(keys: &[C::G]) -> Result<u16, MusigKeyError<C>> {
  if keys.is_empty() {
    Err(MusigKeyError::NoKeysProvided)?;
  }

  let keys_len = u16::try_from(keys.len())
    .map_err(|_| MusigKeyError::TooManyKeysProvided { max: u16::MAX, provided: keys.len() })?;

  let mut set = HashSet::with_capacity(keys.len());
  for key in keys {
    let bytes = key.to_bytes().as_ref().to_vec();
    if !set.insert(bytes) {
      Err(MusigKeyError::DuplicatedParticipant(*key))?;
    }
  }

  Ok(keys_len)
}

fn binding_factor_transcript<C: Ciphersuite>(
  context: [u8; 32],
  keys_len: u16,
  keys: &[C::G],
) -> Vec<u8> {
  debug_assert_eq!(usize::from(keys_len), keys.len());

  let mut transcript = vec![];
  transcript.extend(&context);
  transcript.extend(keys_len.to_le_bytes());
  for key in keys {
    transcript.extend(key.to_bytes().as_ref());
  }
  transcript
}

fn binding_factor<C: Ciphersuite>(mut transcript: Vec<u8>, i: u16) -> C::F {
  transcript.extend(i.to_le_bytes());
  C::F::from_uniform_bytes(&C::H::digest(&transcript).into())
}

#[expect(clippy::type_complexity)]
fn musig_key_multiexp<C: Ciphersuite>(
  context: [u8; 32],
  keys: &[C::G],
) -> Result<Vec<(C::F, C::G)>, MusigKeyError<C>> {
  let keys_len = check_keys::<C>(keys)?;
  let transcript = binding_factor_transcript::<C>(context, keys_len, keys);
  let mut multiexp = Vec::with_capacity(keys.len());
  for i in 1 ..= keys_len {
    multiexp.push((binding_factor::<C>(transcript.clone(), i), keys[usize::from(i - 1)]));
  }
  Ok(multiexp)
}

/// The group key resulting from using this library's MuSig key aggregation.
///
/// This key will be derived from the list as it is, with the exact ordering affecting the
/// resulting key.
///
/// This function executes in variable time and MUST NOT be used with secret data.
pub fn musig_key_vartime<C: Ciphersuite>(
  context: [u8; 32],
  keys: &[C::G],
) -> Result<C::G, MusigKeyError<C>> {
  Ok(multiexp::multiexp_vartime(&musig_key_multiexp::<C>(context, keys)?))
}

/// The group key resulting from using this library's MuSig key aggregation.
///
/// This key will be derived from the list as it is, with the exact ordering affecting the
/// resulting key.
pub fn musig_key<C: Ciphersuite>(
  context: [u8; 32],
  keys: &[C::G],
) -> Result<C::G, MusigKeyError<C>> {
  Ok(multiexp::multiexp(&musig_key_multiexp::<C>(context, keys)?))
}

/// A n-of-n non-interactive DKG which does not guarantee the usability of the resulting key.
///
/// The resulting key will be derived from the list as it is, with the exact ordering affecting the
/// resulting key.
pub fn musig<C: Ciphersuite>(
  context: [u8; 32],
  private_key: Zeroizing<C::F>,
  keys: &[C::G],
) -> Result<ThresholdKeys<C>, MusigError<C>> {
  let our_pub_key = C::generator() * private_key.deref();
  let Some(our_i) = keys.iter().position(|key| *key == our_pub_key) else {
    Err(MusigError::DkgError(DkgError::NotParticipating))?
  };

  let keys_len: u16 = check_keys::<C>(keys).map_err(MusigError::MusigKeyError)?;

  let params = ThresholdParams::new(
    keys_len,
    keys_len,
    // The `+ 1` won't fail as `keys.len() <= u16::MAX`, so any index is `< u16::MAX`
    Participant::new(
      u16::try_from(our_i).expect("keys.len() <= u16::MAX yet index of keys > u16::MAX?") + 1,
    )
    .expect("i + 1 != 0"),
  )
  .map_err(MusigError::DkgError)?;

  let transcript = binding_factor_transcript::<C>(context, keys_len, keys);
  let mut binding_factors = Vec::with_capacity(keys.len());
  let mut multiexp = Vec::with_capacity(keys.len());
  let mut verification_shares = HashMap::with_capacity(keys.len());
  for (i, key) in (1 ..= keys_len).zip(keys.iter().copied()) {
    let binding_factor = binding_factor::<C>(transcript.clone(), i);
    binding_factors.push(binding_factor);
    multiexp.push((binding_factor, key));

    let i = Participant::new(i).expect("non-zero u16 wasn't a valid Participant index?");
    verification_shares.insert(i, key);
  }
  let group_key = multiexp::multiexp(&multiexp);
  debug_assert_eq!(our_pub_key, verification_shares[&params.i()]);
  core::debug_assert_matches!(musig_key_vartime::<C>(context, keys), Ok(key) if key == group_key);

  ThresholdKeys::new(
    params,
    Interpolation::Constant(binding_factors),
    private_key,
    verification_shares,
  )
  .map_err(MusigError::DkgError)
}
