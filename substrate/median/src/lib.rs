#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

use core::cmp::Ordering;

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use scale::{EncodeLike, FullCodec};
use frame_support::storage::*;

mod lexicographic;
pub use lexicographic::*;

mod average;
pub use average::*;

mod policy;
pub use policy::*;

/// The store for a median.
///
/// `KeyPrefix` is accepted so a single set of storage values may be used to back multiple medians.
/// For all `(Iterable)StorageDoubleMap`s however, the hasher of the second key MUST be the
/// identity hasher. This is due to relying on the ordering of the keys to achieve iteration
/// through elements of the list of values for which the median is taken.
///
/// With a radix trie, the storage hasher is intended to limit the ability of an adversary to
/// create complex layouts which have increased costs to read/write/prove. With a proper choice of
/// hasher, while an adversary may be able to write to certain keys in an attempt to add additional
/// layers to the trie (decreasing performance), they'd have to continually perform hashes and find
/// partial collisions (a task which becomes more and more difficult as the adversary attempts to
/// add more and more additional layers). The requirement of the identity hasher here does nullify
/// that protection. Accordingly, when deploying a median, the values inserted must either be
/// infeasible to manipulate or the length of their encodings must be sufficiently small that even
/// if an attacker created the most complex layout possible, it'd still be of tolerable complexity.
///
/// For all storage values present, they MUST be considered opaque to the caller and left
/// undisturbed. No assumptions may be made about their internal representation nor usage.
/// Any names or documentation comments are solely for the review of the implementation
/// itself, and are not intended to signify any potential layout nor use cases to the caller.
/// ANY external usage has undefined behavior.
pub trait MedianStore<KeyPrefix: FullCodec, MedianValue: Average + LexicographicEncoding> {
  /// The policy to use when there are multiple candidate values.
  const POLICY: Policy;

  /// The amount of items currently present within the median's list.
  type Length: StorageMap<KeyPrefix, u64, Query = u64>;

  /// A store for the values currently present within the median.
  ///
  /// The value is the amount of instances of this value within the median's list.
  type Store: IterableStorageDoubleMap<KeyPrefix, MedianValue::Encoding, u64, Query = u64>;

  /// A secondary store for the values currently present within the median.
  type ReverseStore: IterableStorageDoubleMap<
    KeyPrefix,
    LexicographicReverse<MedianValue>,
    (),
    Query = (),
  >;

  /// The position of the saved median within the list of values.
  ///
  /// This is necessary as when a value selected as the current median is present multiple times
  /// within the list of values, the code does not know _which_ instance was selected as the
  /// median, as necessary to know when to advance to a lesser/greater value. To resolve this, once
  /// we know a value is the median value, we always set the position to the _first instance_ of
  /// the value. This gives us a consistent frame of reference to decide the next steps of the
  /// algorithm upon.
  type Position: StorageMap<KeyPrefix, u64, Query = Option<u64>>;

  /// The median value.
  ///
  /// This may drift from the actual median while an update is performed.
  type Median: StorageMap<KeyPrefix, MedianValue, Query = Option<MedianValue>>;
}

const KEY_PREFIX_ASSERT: &str = "next value in storage had a different prefix associated";
const AFTER_ASSERT: &str = "iterator yielding *after* key yielded key itself";

/// Update the median.
///
/// This function may be called at any point to correctly calculate the current median. It will do
/// so in an amount of operations linear to the distance from the stored median to the new median.
///
/// Since the distance is bounded by the amount of insertions to/removals from the median's list
/// which have yet to be handled, the following `push` and `pop` functions achieve a constant
/// amount of operations by calling this function _upon each and every invocation_. This leaves
/// solely a singular insertion/removal needing to be handled, and a maximum distance of one.
fn update_median<
  KeyPrefix: FullCodec,
  MedianValue: Average + LexicographicEncoding,
  S: MedianStore<KeyPrefix, MedianValue>,
>(
  key_prefix: impl Copy + EncodeLike<KeyPrefix>,
) {
  let Some(mut median_pos) = S::Position::get(key_prefix) else {
    return;
  };
  let length = S::Length::get(key_prefix);
  let target_median_pos = S::POLICY.target_median_pos(length);

  let mut median = S::Median::get(key_prefix).expect("current position yet not current median");

  // We first iterate up to the desired median position
  {
    let mut iter = {
      let median_key = S::Store::hashed_key_for(key_prefix, median.lexicographic_encode());
      S::Store::iter_from(median_key)
    };

    let mut median_instances = S::Store::get(key_prefix, median.lexicographic_encode());
    let mut next_value_first_pos;
    while {
      next_value_first_pos = median_pos + median_instances;
      next_value_first_pos <= target_median_pos
    } {
      median_pos = next_value_first_pos;
      #[cfg_attr(debug_assertions, allow(clippy::used_underscore_binding))]
      let (_key_prefix, next_value_encoding, next_value_instances) = iter
        .next()
        .expect("stored median was before the actual median yet no values were after it");
      debug_assert_eq!(key_prefix.encode(), _key_prefix.encode(), "{KEY_PREFIX_ASSERT}");
      debug_assert!(median.lexicographic_encode() != next_value_encoding, "{AFTER_ASSERT}");
      median = MedianValue::lexicographic_decode(next_value_encoding);
      median_instances = next_value_instances;
    }
  }

  // Then, we iterate down to the desired median position
  /*
    Only one of these loops should actually execute. Presenting them sequentially is just the most
    straightforward way to write this function.
  */
  {
    let mut iter = {
      let median_key =
        S::ReverseStore::hashed_key_for(key_prefix, LexicographicReverse::from(&median));
      S::ReverseStore::iter_keys_from(median_key)
    };

    while median_pos > target_median_pos {
      #[cfg_attr(debug_assertions, allow(clippy::used_underscore_binding))]
      let (_key_prefix, prior_value_encoding) = iter
        .next()
        .expect("stored median was before the actual median yet no values were after it");
      debug_assert_eq!(key_prefix.encode(), _key_prefix.encode(), "{KEY_PREFIX_ASSERT}");
      let prior_value = prior_value_encoding.into();
      debug_assert!(prior_value != median, "{AFTER_ASSERT}");
      let prior_value_instances = S::Store::get(key_prefix, prior_value.lexicographic_encode());
      median = prior_value;
      median_pos -= prior_value_instances;
    }
  }

  // Save the result
  S::Position::set(key_prefix, Some(median_pos));
  S::Median::set(key_prefix, Some(median));
}

/// A median.
///
/// The implementation only uses a constant amount of database operations to implement insertion
/// and removal. When instantiated over a database with logarithmic complexities (such as a radix
/// trie), this effects a median with logarithmic memory/computation complexities (not requiring
/// loading all values into memory).
///
/// This SHOULD NOT be used for small collections where the linear (or even quadratic) complexities
/// still out-perform how expensive database operations are. In those cases, the collection should
/// be written to a single storage slot, read entirely, sorted, and the median should be
/// immediately taken via indexing the value halfway through the collection.
pub trait Median<KeyPrefix: FullCodec, MedianValue: Average + LexicographicEncoding>:
  MedianStore<KeyPrefix, MedianValue>
{
  /// The current length of the median's list.
  fn length(key_prefix: impl Copy + EncodeLike<KeyPrefix>) -> u64;

  /// The current median value.
  ///
  /// This returns `None` if no values are present.
  fn median(key_prefix: impl Copy + EncodeLike<KeyPrefix>) -> Option<MedianValue>;

  /// Push a new value onto the median.
  ///
  /// If the value is already present within the existing values, the amount of times it will be
  /// considered present will be incremented.
  fn push(key_prefix: impl Copy + EncodeLike<KeyPrefix>, value: MedianValue);

  /// Remove a value from the median's list.
  ///
  /// This returns `true` if the value was present and `false` otherwise.
  ///
  /// If the value is present within the existing values multiple times, only a single instance
  /// will be removed.
  fn pop(key_prefix: impl Copy + EncodeLike<KeyPrefix>, value: MedianValue) -> bool;
}

impl<
    KeyPrefix: FullCodec,
    MedianValue: Average + LexicographicEncoding,
    S: MedianStore<KeyPrefix, MedianValue>,
  > Median<KeyPrefix, MedianValue> for S
{
  fn length(key_prefix: impl Copy + EncodeLike<KeyPrefix>) -> u64 {
    Self::Length::get(key_prefix)
  }

  /*
    This function assumes `Position`, `Median` are up to date. This is guaranteed by
    `update_median` being called after every single `push`, `pop` call, the only defined ways to
    mutate the state.
  */
  fn median(key_prefix: impl Copy + EncodeLike<KeyPrefix>) -> Option<MedianValue> {
    let mut current_median = Self::Median::get(key_prefix)?;
    // If we're supposed to take the average, do so now
    if matches!(S::POLICY, Policy::Average) {
      let length = Self::length(key_prefix);
      if (length % 2) == 0 {
        // This will yield the target position for the lesser value in the pair
        let target_median_pos_lo = Self::POLICY.target_median_pos(length);
        let target_median_pos_hi = target_median_pos_lo + 1;

        /*
          We need to take the average of the current value and the next value, due to
          `Policy::Average` internally being considered `Policy::Lesser` and solely differing here
          when the median is fetched.

          To fetch the next value, we first need to identify if `target_median_pos` points to the
          _last instance_ of the currently selected median value. If it does not, then the next
          value is another instance of this value, the average of them themselves, and we can
          return now.

          If `target_median_pos` does point to the last instance of the currently selected median
          value, then we fetch the next key in our trie to learn the next value in order to take the
          average.
        */
        let current_median_pos =
          Self::Position::get(key_prefix).expect("current median yet no position");
        let current_median_encoding = current_median.lexicographic_encode();
        let inclusions = Self::Store::get(key_prefix, &current_median_encoding);
        let start_pos_of_next_value = current_median_pos + inclusions;

        // Short-circuit if we are averaging two of the same value
        if target_median_pos_hi < start_pos_of_next_value {
          return Some(current_median);
        }

        let current_median_key = Self::Store::hashed_key_for(key_prefix, &current_median_encoding);
        #[cfg_attr(debug_assertions, allow(clippy::used_underscore_binding))]
        let (_key_prefix, next_encoding) = Self::Store::iter_keys_from(current_median_key)
          .next()
          .expect("last value in storage yet looking for value after it");
        debug_assert_eq!(key_prefix.encode(), _key_prefix.encode(), "{KEY_PREFIX_ASSERT}");
        debug_assert!(current_median_encoding != next_encoding, "{AFTER_ASSERT}");
        let next_value = MedianValue::lexicographic_decode(next_encoding);

        current_median = MedianValue::average(current_median, next_value);
      }
    }
    Some(current_median)
  }

  fn push(key_prefix: impl Copy + EncodeLike<KeyPrefix>, value: MedianValue) {
    // Update the length
    let existing_length = Self::Length::get(key_prefix);
    let new_length = existing_length + 1;
    Self::Length::set(key_prefix, new_length);

    // Update the amount of inclusions
    let encoding = value.lexicographic_encode();
    {
      let existing_presences = Self::Store::get(key_prefix, &encoding);
      let new_presences = existing_presences + 1;
      Self::Store::set(key_prefix, &encoding, new_presences);
      if existing_presences == 0 {
        Self::ReverseStore::set(key_prefix, LexicographicReverse::from_encoding(encoding), ());
      }
    }

    // If this was the first value inserted, initialize and immediately return
    if existing_length == 0 {
      Self::Position::set(key_prefix, Some(0));
      Self::Median::set(key_prefix, Some(value));
      return;
    }

    // Fetch the current median
    let existing_median =
      Self::Median::get(key_prefix).expect("values within median yet no median");

    // If this value was inserted before the current median, the current median's position has
    // increased
    if value < existing_median {
      let mut existing_median_pos =
        Self::Position::get(key_prefix).expect("values within median yet no current position");
      existing_median_pos += 1;
      Self::Position::set(key_prefix, Some(existing_median_pos));
    }

    // Update the median
    update_median::<_, _, Self>(key_prefix);
  }

  fn pop(key_prefix: impl Copy + EncodeLike<KeyPrefix>, value: MedianValue) -> bool {
    let encoding = value.lexicographic_encode();
    let mut inclusions = Self::Store::get(key_prefix, &encoding);
    if inclusions == 0 {
      return false;
    }

    // Update the length
    let existing_length = Self::Length::get(key_prefix);
    let new_length = existing_length - 1;
    Self::Length::set(key_prefix, new_length);

    // Update the presence within the median's list
    inclusions -= 1;
    if inclusions == 0 {
      Self::Store::remove(key_prefix, &encoding);
      Self::ReverseStore::remove(key_prefix, LexicographicReverse::from_encoding(encoding));
    } else {
      Self::Store::set(key_prefix, encoding, inclusions);
    }

    let existing_median =
      Self::Median::get(key_prefix).expect("values within median yet no median");
    match value.cmp(&existing_median) {
      Ordering::Less => {
        let mut existing_median_pos =
          Self::Position::get(key_prefix).expect("values within median yet no current position");
        existing_median_pos -= 1;
        Self::Position::set(key_prefix, Some(existing_median_pos));
      }

      Ordering::Equal if inclusions == 0 => {
        /*
          This value was the median, then removed, leaving `Median` and `Position` in an
          ill-defined state. We attempt to consider `Position` as well-defined and solely update
          `Median` to also be well-defined.

          This works so long `Position` still refers to a valid position within the median's list.
          It may not if the median's list started with length 1 or 2, where the current position
          could have referred to the last element in the list, now popped.

          If the length was 1, the list is now empty, triggering its own special case.

          If the length was 2, we create a well-defined (and also accurate) definition for
          `Position` and `Median` by setting them to the first (and only) item within
          the list.
        */
        if new_length == 0 {
          Self::Position::remove(key_prefix);
          Self::Median::remove(key_prefix);
        } else {
          let existing_median_pos =
            Self::Position::get(key_prefix).expect("values within median yet no current position");

          let new_median_encoding = if existing_median_pos >= new_length {
            /*
              While resetting the declared median to the first item is always safe, so long as
              `update_median` is called after (as done here), `update_median` has an algorithmic
              complexity linear to the distance from the declared median to the correct median.
              That means this can only be done, while maintaining the desired complexities, when a
              bound is known on the distance from `0` to `target_median_pos`.

              Since the list length is 1 in this case, per the reasoning above, the distance here
              is `0`, making this a safe operation which also respects the desired complexities.
            */
            Self::Position::set(key_prefix, Some(0));
            Self::Store::iter_key_prefix(key_prefix)
              .next()
              .expect("median list isn't empty yet has no values")
          } else {
            let existing_median_key =
              Self::Store::hashed_key_for(key_prefix, existing_median.lexicographic_encode());
            #[cfg_attr(debug_assertions, allow(clippy::used_underscore_binding))]
            let (_key_prefix, next_value_encoding) =
              Self::Store::iter_keys_from(existing_median_key)
                .next()
                .expect("current median wasn't the last value yet no value was after");
            debug_assert_eq!(key_prefix.encode(), _key_prefix.encode(), "{KEY_PREFIX_ASSERT}");
            debug_assert!(
              existing_median.lexicographic_encode() != next_value_encoding,
              "{AFTER_ASSERT}",
            );
            next_value_encoding
          };

          Self::Median::set(
            key_prefix,
            Some(MedianValue::lexicographic_decode(new_median_encoding)),
          );
        }
      }

      /*
        If this value is an instance of the current median, for which some remain, we consider this
        as removing an instance other than the first instance which is what the position refers to.
        Accordingly, we don't have to update the position.

        If this is greater than the current median, then its removal does not effect the position
        of the current median.
      */
      Ordering::Equal | Ordering::Greater => {}
    }

    // Update the median
    update_median::<_, _, Self>(key_prefix);

    true
  }
}
