#[cfg(feature = "std")]
use core::ops::Deref;
use std_shims::{vec, vec::Vec, collections::HashSet};
#[cfg(feature = "std")]
use std_shims::collections::HashMap;

#[cfg(feature = "std")]
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use ciphersuite::group::ff::Field;
use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite,
};

use crate::DkgError;
#[cfg(feature = "std")]
use crate::{Participant, ThresholdParams, ThresholdCore, lagrange};

fn check_keys<C: Ciphersuite>(keys: &[C::G]) -> Result<u16, DkgError<()>> {
  if keys.is_empty() {
    Err(DkgError::InvalidSigningSet)?;
  }
  // Too many signers
  let keys_len = u16::try_from(keys.len()).map_err(|_| DkgError::InvalidSigningSet)?;

  // Duplicated public keys
  if keys.iter().map(|key| key.to_bytes().as_ref().to_vec()).collect::<HashSet<_>>().len() !=
    keys.len()
  {
    Err(DkgError::InvalidSigningSet)?;
  }

  Ok(keys_len)
}

// This function panics if called with keys whose length exceed 2**16.
// This is fine since it's internal and all calls occur after calling check_keys, which does check
// the keys' length.
fn binding_factor_transcript<C: Ciphersuite>(
  context: &[u8],
  keys: &[C::G],
) -> Result<Vec<u8>, DkgError<()>> {
  let mut transcript = vec![];
  transcript.push(u8::try_from(context.len()).map_err(|_| DkgError::InvalidSigningSet)?);
  transcript.extend(context);
  transcript.extend(u16::try_from(keys.len()).unwrap().to_le_bytes());
  for key in keys {
    transcript.extend(key.to_bytes().as_ref());
  }
  Ok(transcript)
}

fn binding_factor<C: Ciphersuite>(mut transcript: Vec<u8>, i: u16) -> C::F {
  transcript.extend(i.to_le_bytes());
  C::hash_to_F(b"musig", &transcript)
}

/// The group key resulting from using this library's MuSig key gen.
///
/// This function will return an error if the context is longer than 255 bytes.
///
/// Creating an aggregate key with a list containing duplicated public keys will return an error.
pub fn musig_key<C: Ciphersuite>(context: &[u8], keys: &[C::G]) -> Result<C::G, DkgError<()>> {
  let keys_len = check_keys::<C>(keys)?;
  let transcript = binding_factor_transcript::<C>(context, keys)?;
  let mut res = C::G::identity();
  for i in 1 ..= keys_len {
    res += keys[usize::from(i - 1)] * binding_factor::<C>(transcript.clone(), i);
  }
  Ok(res)
}

/// A n-of-n non-interactive DKG which does not guarantee the usability of the resulting key.
///
/// Creating an aggregate key with a list containing duplicated public keys returns an error.
#[cfg(feature = "std")]
pub fn musig<C: Ciphersuite>(
  context: &[u8],
  private_key: &Zeroizing<C::F>,
  keys: &[C::G],
) -> Result<ThresholdCore<C>, DkgError<()>> {
  let keys_len = check_keys::<C>(keys)?;

  let our_pub_key = C::generator() * private_key.deref();
  let Some(pos) = keys.iter().position(|key| *key == our_pub_key) else {
    // Not present in signing set
    Err(DkgError::InvalidSigningSet)?
  };
  let params = ThresholdParams::new(
    keys_len,
    keys_len,
    // These errors shouldn't be possible, as pos is bounded to len - 1
    // Since len is prior guaranteed to be within u16::MAX, pos + 1 must also be
    Participant::new((pos + 1).try_into().map_err(|_| DkgError::InvalidSigningSet)?)
      .ok_or(DkgError::InvalidSigningSet)?,
  )?;

  // Calculate the binding factor per-key
  let transcript = binding_factor_transcript::<C>(context, keys)?;
  let mut binding = Vec::with_capacity(keys.len());
  for i in 1 ..= keys_len {
    binding.push(binding_factor::<C>(transcript.clone(), i));
  }

  // Multiply our private key by our binding factor
  let mut secret_share = private_key.clone();
  *secret_share *= binding[pos];

  // Calculate verification shares
  let mut verification_shares = HashMap::new();
  // When this library offers a ThresholdView for a specific signing set, it applies the lagrange
  // factor
  // Since this is a n-of-n scheme, there's only one possible signing set, and one possible
  // lagrange factor
  // In the name of simplicity, we define the group key as the sum of all bound keys
  // Accordingly, the secret share must be multiplied by the inverse of the lagrange factor, along
  // with all verification shares
  // This is less performant than simply defining the group key as the sum of all post-lagrange
  // bound keys, yet the simplicity is preferred
  let included = (1 ..= keys_len)
    // This error also shouldn't be possible, for the same reasons as documented above
    .map(|l| Participant::new(l).ok_or(DkgError::InvalidSigningSet))
    .collect::<Result<Vec<_>, _>>()?;
  let mut group_key = C::G::identity();
  for (l, p) in included.iter().enumerate() {
    let bound = keys[l] * binding[l];
    group_key += bound;

    let lagrange_inv = lagrange::<C::F>(*p, &included).invert().unwrap();
    if params.i() == *p {
      *secret_share *= lagrange_inv;
    }
    verification_shares.insert(*p, bound * lagrange_inv);
  }
  debug_assert_eq!(C::generator() * secret_share.deref(), verification_shares[&params.i()]);
  debug_assert_eq!(musig_key::<C>(context, keys).unwrap(), group_key);

  Ok(ThresholdCore { params, secret_share, group_key, verification_shares })
}
