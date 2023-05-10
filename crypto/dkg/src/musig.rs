use core::ops::Deref;
use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite,
};

use crate::{Participant, DkgError, ThresholdParams, ThresholdCore, lagrange};

/// A n-of-n non-interactive DKG which does not guarantee the usability of the resulting key.
///
/// Creating a key with duplicated public keys returns an error.
pub fn musig<C: Ciphersuite>(
  private_key: &Zeroizing<C::F>,
  keys: &[C::G],
) -> Result<ThresholdCore<C>, DkgError<()>> {
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
  let mut transcript = RecommendedTranscript::new(b"DKG MuSig v0.5");
  transcript.domain_separate(b"musig_binding_factors");
  for key in keys {
    transcript.append_message(b"key", key.to_bytes());
  }

  let mut binding = Vec::with_capacity(keys.len());
  for i in 1 ..= keys_len {
    let mut transcript = transcript.clone();
    transcript.append_message(b"participant", i.to_le_bytes());
    binding
      .push(C::hash_to_F(b"DKG-MuSig-binding_factor", &transcript.challenge(b"binding_factor")));
  }

  // Multiply our private key by our binding factor
  let mut secret_share = private_key.clone();
  *secret_share *= binding[pos];

  // Calculate verification shares
  let mut verification_shares = HashMap::new();
  // When this library generates shares for a specific signing set, it applies the lagrange
  // coefficient
  // Since this is a n-of-n scheme, there's only one possible signing set, and one possible
  // lagrange factor
  // Define the group key as the sum of all verification shares, post-lagrange
  // While we could invert our lagrange factor and multiply it by our secret share, so the group
  // key wasn't post-lagrange, the inversion is ~300 multiplications and we'd have to apply similar
  // inversions + multiplications to all verification shares
  // Accordingly, it'd never be more performant, though it would simplify group key calculation
  let included = (1 ..= keys_len)
    // This error also shouldn't be possible, for the same reasons as documented above
    .map(|l| Participant::new(l).ok_or(DkgError::InvalidSigningSet))
    .collect::<Result<Vec<_>, _>>()?;
  let mut group_key = C::G::identity();
  for (l, p) in included.iter().enumerate() {
    let verification_share = keys[l] * binding[l];
    group_key += verification_share * lagrange::<C::F>(*p, &included);
    verification_shares.insert(*p, verification_share);
  }
  debug_assert_eq!(C::generator() * secret_share.deref(), verification_shares[&params.i()]);

  Ok(ThresholdCore { params, secret_share, group_key, verification_shares })
}
