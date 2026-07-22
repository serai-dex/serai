use alloc::collections::{btree_map, BTreeMap};
use std::collections::{hash_map, HashMap};

use crate::{BlockNumber, Validator, ValidatorSet};

/// A view of validators and the greatest block numbers we've observed them attempting to achieve
/// consensus over.
///
/// This container has memory which is bounded to be approximately linear to the set size.
pub(super) struct ObservedBlockNumbers<V: Validator> {
  /// The greatest observed block number.
  observed_block_number: Option<BlockNumber>,

  /// The greatest block number observed for each validator.
  block_numbers: HashMap<V, BlockNumber>,

  /// The tallies for how many validators (by weight) we've observed attempting to achieve
  /// consensus for a block.
  ///
  /// We use a [`BTreeMap`] to ensure we can iterate over this in an efficient manner.
  block_tallies: BTreeMap<BlockNumber, u16>,

  /// The sum weight of the current tallies.
  tallied_weight: u16,
}

impl<V: Validator> ObservedBlockNumbers<V> {
  /// Create a new instance with a specified capacity.
  #[must_use]
  pub(super) fn new(capacity: usize) -> Self {
    Self {
      observed_block_number: None,
      block_numbers: HashMap::with_capacity(capacity),
      block_tallies: BTreeMap::new(),
      tallied_weight: 0,
    }
  }

  /// Update the block number for a validator.
  ///
  /// If this validator is not already present within this container, an entry will be inserted.
  /// While this increases the memory usage, it's presumed the validator set is constant and
  /// therefore the bound is maintained.
  ///
  /// This will return the greatest block number observed by more than the fault threshold of
  /// validators, if a new decision on that value has been made. When a new decision is made,
  /// tallies for all blocks less than or equal to the returned value will be pruned. This means
  /// the caller MUST handle the return value and not expect it to be continuously yielded.
  #[must_use]
  pub(super) fn update(
    &mut self,
    validator_set: &(impl ?Sized + ValidatorSet<Validator = V>),
    validator: V,
    block_number: BlockNumber,
  ) -> Option<BlockNumber> {
    // Short-circuit if we've already observed this or a greater block number
    if self.observed_block_number >= Some(block_number) {
      None?;
    }

    let validator_weight = validator_set.weight(&validator).map(u16::from).unwrap_or(0);

    match self.block_numbers.entry(validator) {
      hash_map::Entry::Occupied(mut entry) => {
        let existing_block_number = *entry.get();

        // Short-circuit if this isn't a greater observed block number for this validator
        if existing_block_number >= block_number {
          None?;
        }
        entry.insert(block_number);

        // If this points to a live tally, subtract this validator's weight now
        match self.block_tallies.entry(existing_block_number) {
          btree_map::Entry::Occupied(mut entry) => {
            *entry.get_mut() -= validator_weight;
            if (*entry.get()) == 0 {
              entry.remove();
            }
            self.tallied_weight -= validator_weight;
          }
          btree_map::Entry::Vacant(_) => {
            debug_assert!(Some(existing_block_number) <= self.observed_block_number);
          }
        }
      }
      hash_map::Entry::Vacant(entry) => {
        entry.insert(block_number);
      }
    }
    debug_assert_eq!(self.block_numbers[&validator], block_number);

    /*
      Add this validator's weight to the tally for the greatest block number we've observed for
      them.
    */
    self
      .block_tallies
      .entry(block_number)
      .and_modify(|weight| *weight += validator_weight)
      .or_insert(validator_weight);
    self.tallied_weight += validator_weight;

    // The fault threshold has to be _passed_ for us to consider this block observed
    let mut needed_weight_minus_one = validator_set.fault_threshold();
    /*
      If our map does not have enough weight for this threshold, short-circuit now.

      This causes this function to have O(1) complexity, not O(n) complexity, in the average case.
      This is caveated as the map lookups are actually of O(log n) complexity, and the `BTreeMap`
      used for `block_tallies` can be forced from `O(log n)` to `O(n)` by an adversary. We accept
      the risk regarding the `BTreeMap` as:
      1) We want the efficient iteration over its entries (by ordinality)
      2) It's bounded to O(f)
    */
    if self.tallied_weight <= needed_weight_minus_one {
      None?;
    }

    /*
      Find the greatest block number for which we've observed more than the fault threshold of
      validators attempting to achieve consensus.
    */
    let result = {
      #[cfg(debug_assertions)]
      let mut last_block_number = None;
      let mut result = None;
      for (block_number, weight) in self.block_tallies.iter().rev() {
        #[cfg(debug_assertions)]
        {
          if let Some(last_block_number) = last_block_number {
            debug_assert!(block_number < last_block_number);
          }
          last_block_number = Some(block_number);
        }

        match needed_weight_minus_one.checked_sub(*weight) {
          Some(remaining) => needed_weight_minus_one = remaining,
          None => {
            result = Some(*block_number);
            break;
          }
        }
      }
      result.expect("tallied weight exceeded needed weight yet no decision")
    };

    // Update the greatest observed block number internally
    self.observed_block_number = Some(result);

    /*
      Prune all entries less than or equal to the greatest observed block number to ensure this map
      is minimal.
    */
    for (_block_number, weight) in self.block_tallies.extract_if(..= result, |_, _| true) {
      self.tallied_weight -= weight;
    }

    Some(result)
  }
}
