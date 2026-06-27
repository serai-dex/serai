#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::ops::{Deref as _, DerefMut as _};
extern crate alloc;
use alloc::{vec::Vec, vec};

use zeroize::Zeroizing;

use ciphersuite::{GroupIo, Id};

pub use dkg::*;

/// Errors encountered when recovering a secret-shared key`.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RecoveryError {
  /// No keys were provided.
  #[error("no keys provided")]
  NoKeysProvided,
  /// Not enough keys were provided.
  #[error("not enough keys provided (threshold required {required}, provided {provided})")]
  NotEnoughKeysProvided {
    /// The amount of keys which were required.
    required: u16,
    /// The amount of keys which were provided.
    provided: usize,
  },
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

/// Recover a shared secret from a collection of [`dkg::ThresholdKeys`].
///
/// This function assumes `keys` contains no entries for which
/// `keys_i.params().i() == keys_j.params().i()`. It may spuriously error (with incorrect
/// description) when such keys are passed to it.
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

/// Increment a list representing all possible permutations of a search space.
///
/// This is intended for permutating a set of size `<= slots.len()` and accordingly uses `None` to
/// represent no selected value. `None` is the only value which may appear multiple times. For the
/// values which are `Some`, their values will be unique and the result will be sorted.
///
/// This returns `false` if the permutations have been exhausted, as defined by having already
/// yielded every unique set for which every member is _less than_ `Some(limit)`. In that case,
/// `slots` is left as an undefined value.
#[must_use]
fn permutation(slots: &mut [Option<u16>], limit: u16) -> bool {
  let Some(mut i) = slots.len().checked_sub(1) else { return false };
  if limit == 0 {
    return false;
  }

  // Increment the latest index we can
  loop {
    let slots_len = slots.len();
    let Some(slot_value) = &mut slots[i] else {
      slots[i] = Some(0);
      break;
    };

    if let Some(increment) = slot_value.checked_add(1) {
      // If this index is at its limit, retry with the prior index
      let final_increment =
        increment.saturating_add(u16::try_from(slots_len - 1 - i).unwrap_or(u16::MAX));
      if final_increment >= limit {
        if i == 0 {
          return false;
        }
        i -= 1;
        continue;
      }

      // Assign this slot to its increment
      *slot_value = increment;
      break;
    }
  }

  // For the slot we incremented, initialize the following slots
  {
    let mut assigned_value = slots[i].expect("didn't assign a value in the above permutation loop");
    for slot in slots.iter_mut().skip(i + 1) {
      // This was checked when we checked `final_increment`
      let incremented = assigned_value + 1;
      assigned_value = incremented;
      *slot = Some(assigned_value);
    }
    if assigned_value >= limit {
      return false;
    }
  }

  // Check this permutation is in the expected form
  for i in 1 .. slots.len() {
    debug_assert!(slots[i - 1] <= slots[i]);
    if slots[i - 1].is_some() {
      debug_assert!(slots[i - 1] < slots[i]);
    }
  }
  // Check the limit is still respected
  debug_assert!(slots.last() <= Some(&Some(limit)));

  true
}

/// Recover a shared secret from a collection of [`dkg::ThresholdKeys`], ensuring the result is
/// singular.
///
/// This performs a recovery for every possible permutation of the input keys, and accordingly has
/// factorial complexity. It's intended for ensuring that any set of shares from a DKG as usable as
/// intended. It SHOULD NOT be used for large set sizes.
///
/// This function assumes `keys` contains no entries for which
/// `keys_i.params().i() == keys_j.params().i()`. It may spuriously error (with incorrect
/// description) when such keys are passed to it.
// TODO: Alternatively, a set of size the threshold could reconstruct the entire original
// polynomial before re-dealing the secret shares and checking their equivalence to the existing
// secret shares. This would avoid performing a permutation and wouldn't have quadratic complexity.
pub fn recover_singular_key<C: GroupIo + Id>(
  keys: &[ThresholdKeys<C>],
) -> Result<Zeroizing<C::F>, RecoveryError> {
  let t_present = keys.len();
  let t_necessary = keys.first().ok_or(RecoveryError::NoKeysProvided)?.params().t();

  let mut to_remove = vec![
    None;
    t_present.checked_sub(usize::from(t_necessary)).ok_or(
      RecoveryError::NotEnoughKeysProvided { required: t_necessary, provided: t_present }
    )?
  ];
  let mut recovered = None;
  while {
    let mut keys = keys.to_vec();
    for (i, to_remove) in to_remove.iter().flatten().enumerate() {
      keys.remove(usize::from(*to_remove) - i);
    }
    let recovered_i = recover_key(&keys)?;
    if recovered.is_none() {
      recovered = Some(recovered_i.clone());
    }
    if recovered != Some(recovered_i) {
      Err(RecoveryError::Failure)?;
    }

    let n = u16::try_from(to_remove.len()).map_err(|_| RecoveryError::Failure)?;
    permutation(&mut to_remove, n)
  } {}
  Ok(recovered.unwrap())
}

#[test]
fn test_permutation() {
  // An empty set cannot be permutated
  assert!(!permutation(&mut [], 1));
  // When the limit is the first value incremented to, there are not further permutations
  assert!(!permutation(&mut [None], 0));

  {
    let mut set = [None];

    assert!(permutation(&mut set, 2));
    assert_eq!(set, [Some(0)]);
    assert!(permutation(&mut set, 2));
    assert_eq!(set, [Some(1)]);

    assert!(!permutation(&mut set, 2));
  }

  {
    let mut set = [None, None];

    assert!(permutation(&mut set, 2));
    assert_eq!(set, [None, Some(0)]);
    assert!(permutation(&mut set, 2));
    assert_eq!(set, [None, Some(1)]);
    assert!(permutation(&mut set, 2));
    assert_eq!(set, [Some(0), Some(1)]);

    assert!(!permutation(&mut set, 2));
  }

  {
    let mut set = [None, None, None];

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, None, Some(0)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, None, Some(1)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, None, Some(2)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, None, Some(3)]);

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(0), Some(1)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(0), Some(2)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(0), Some(3)]);

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(1), Some(2)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(1), Some(3)]);

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [None, Some(2), Some(3)]);

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [Some(0), Some(1), Some(2)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [Some(0), Some(1), Some(3)]);
    assert!(permutation(&mut set, 4));
    assert_eq!(set, [Some(0), Some(2), Some(3)]);

    assert!(permutation(&mut set, 4));
    assert_eq!(set, [Some(1), Some(2), Some(3)]);

    assert!(!permutation(&mut set, 2));
  }
}
