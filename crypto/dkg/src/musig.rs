#[cfg(feature = "std")]
use core::ops::Deref;
use std_shims::{vec, vec::Vec, collections::HashSet};
#[cfg(feature = "std")]
use std_shims::collections::HashMap;

#[cfg(feature = "std")]
use zeroize::Zeroizing;

use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite,
};

use crate::DkgError;
#[cfg(feature = "std")]
use crate::{Participant, ThresholdParams, Interpolation, ThresholdCore};

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

  // Our secret share is our private key
  let secret_share = private_key.clone();

  // Calculate verification shares
  let mut verification_shares = HashMap::new();
  let mut group_key = C::G::identity();
  for l in 1 ..= keys_len {
    let key = keys[usize::from(l) - 1];
    group_key += key * binding[usize::from(l - 1)];

    // These errors also shouldn't be possible, for the same reasons as documented above
    verification_shares.insert(Participant::new(l).ok_or(DkgError::InvalidSigningSet)?, key);
  }
  debug_assert_eq!(C::generator() * secret_share.deref(), verification_shares[&params.i()]);
  debug_assert_eq!(musig_key::<C>(context, keys).unwrap(), group_key);

  Ok(ThresholdCore::new(
    params,
    Interpolation::Constant(binding),
    secret_share,
    verification_shares,
  ))
}
