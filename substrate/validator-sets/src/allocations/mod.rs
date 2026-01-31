//! `Allocations` is a simple abstraction over a pair of `StorageMap`s which ensure they remain
//! synchronized and enable iterating over validators by the amount they've allocated. This is used
//! to select validators for new sessions.

use scale::{Encode as _, DecodeAll as _};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    network_id::{ExternalNetworkId, NetworkId},
    balance::Amount,
    validator_sets::KeyShares,
  },
  economic_security::EconomicSecurity as _,
};

use frame_support::storage::{StorageMap, StoragePrefixedMap};

mod sorted_key;
pub(crate) use sorted_key::*;

mod delayed;
pub use delayed::*;

use crate::{Config, auxiliary_keys::AuxiliaryKeys as _};

/// The key to use for the allocations map.
pub(crate) type AllocationsKey = (NetworkId, SeraiAddress);

/// An error when allocating.
#[derive(
  Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
pub enum AllocationError {
  /// The validator set didn't define an allocation requirement for a key share.
  NoAllocationPerKeyShareSet,
  /// Validator is missing necessary auxiliary keys.
  MissingAuxiliaryKeys,
  /// The allocation is less than the requirement for a key share.
  AllocationLessThanKeyShare,
  /// This allocation would introduce a single point of failure.
  IntroducesSinglePointOfFailure,
}

/// An error when deallocating.
#[derive(
  Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
pub enum DeallocationError {
  /// The validator set didn't define an allocation requirement for a key share.
  NoAllocationPerKeyShareSet,
  /// Not enough was allocated to enable this amount to be deallocated.
  NotEnoughAllocated,
  /// The remaining allocation was non-zero and would be less than a key share.
  RemainingAllocationLessThanKeyShare,
  /// This deallocation would introduce a single point of failure.
  IntroducesSinglePointOfFailure,
  /// This deallocation would cause the economic security target to be (further) unsatisfied.
  EconomicSecurity,
}

/// The storage underlying `Allocations`.
pub(crate) trait AllocationsStorage: crate::AuxiliaryKeysStorage {
  /// The allocation required for a key share (or unit of voting weight) on a network.
  ///
  /// The usage of is shared with the rest of the pallet. `Allocations` only reads it to limit
  /// allocations made which wouldn't be eligible to be selected.
  type AllocationPerKeyShare: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// An map storing allocations.
  ///
  /// This is opaque and to be exclusively read/write by `Allocations`.
  ///
  /// Internally, this is used to be able to lookup a validator's allocations by their stake. We
  /// cannot do so with the `SortedAllocations` map due to embedding the allocation itself (the
  /// value we want to look up) into the key.
  type Allocations: StorageMap<AllocationsKey, Amount, Query = Option<Amount>>;

  /// An map storing allocations in a sorted manner.
  ///
  /// This MUST be instantiated with a map using `Identity` for its hasher.
  ///
  /// This is opaque and to be exclusively read/write by `Allocations`.
  type SortedAllocations: StorageMap<SortedAllocationsKey, (), Query = Option<()>>
    + StoragePrefixedMap<()>;
}

/// An interface for managing validators' allocations.
pub(crate) trait Allocations {
  /// Get an allocation.
  ///
  /// If a validator has an allocation, it means they're technically eligible to be a validator,
  /// having the required auxiliary keys declared. It does not mean they have a sufficient
  /// allocation for a key share however, which must be checked by the caller.
  fn allocation(network: NetworkId, key: SeraiAddress) -> Option<Amount>;

  /// Iterate over the allocations for a network, ordered from most to least allocated.
  ///
  /// The iterator is lazy and will yield additional items until no remaining validators have an
  /// allocation greater than or equal to the specified minimum. The minimum MUST be specified to a
  /// sane value as the allocations present within the `StorageMap` are not guaranteed to be within
  /// any range. Per [`frame-support`]'s bounds, modifying the storage while holding this iterator
  /// will lead to undefined behavior.
  ///
  /// If two validators share an allocation, the order is deterministic (will be consistent if
  /// again queried against an identical state) yet the tie-breaking mechanism is unspecified and
  /// left as an implementation detail.
  fn iter_allocations(
    network: impl Into<NetworkId>,
    minimum_allocation: Amount,
  ) -> impl Iterator<Item = (SeraiAddress, Amount)>;

  /// Increase a validator's allocation, without updating any other contexts.
  ///
  /// This will validate the allocation follows policy, such as current bounds on minimum/maximum
  /// allocations, if this is not a reward. Rewards will always be allowed, without error, for any
  /// validator who has set auxiliary keys. This function will not update any storage not
  /// immediately present here nor emit any events.
  ///
  /// Despite validating this allocation causes the validator to qualify for at least one key
  /// share, it does not ensure the storage will only contain validators which qualify for at least
  /// one key share. This is due to the potential for `AllocationPerKeyShare` to be independently
  /// updated, potentially increasing the value _past_ what some validators have currently
  /// allocated. It solely applies the minimum bound to prevent trivial entries from being written
  /// to storage.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for the allocation with regards to the `Allocations` abstraction present here.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(())`.
  fn increase_allocation_without_updating_other_contexts(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
    reward: bool,
  ) -> Result<(), AllocationError>;

  /// Decrease a validator's allocation, without updating any other contexts.
  ///
  /// This will validate the deallocation follows policy. It will not update any storage not
  /// immediately present here nor emit any events.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for the deallocation with regards to the `Allocations` abstraction present here.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(())`.
  fn decrease_allocation_without_updating_other_contexts(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> Result<(), DeallocationError>;

  /// Drain a validator's allocation.
  ///
  /// This is intended to be called in response to a fatal slash. It will set the validator's
  /// allocation to `0` regardless of the context.
  ///
  /// This function will return the `Amount` drained.
  fn drain_allocation(network: NetworkId, validator: SeraiAddress) -> Option<Amount>;
}

/*
  Given how the `KeyShares` type enforces any instance is `<= KeyShares::MAX_PER_SET`, we want to
  enforce two specific derivative properties:

  1) Any two instances of key shares may be summed together without overflowing its representation.
     This lets us safely iterate while performing a sum, terminating
     _immediately at or past the limit_, without concerns of overflow. This requires
     `2 * KeyShares::MAX_PER_SET` be representable.

  2) That we are able to check if `3 f + 1 <= n` holds for any `f` which is valid as an amount of
     key shares. This requires `4 * KeyShares::MAX_PER_SET` be representable

  We define a constant with a type which is valid if these properties hold true, but invalid if
  they don't, causing an error at time of compile. Specifically, if the boolean condition is true,
  the subtraction results in zero. If it's false, the subtraction would cause an underflow and be
  rejected by the compiler.
*/
#[expect(clippy::as_conversions)]
const _MAX_PER_SET_IS_IN_RANGE: [(); ((KeyShares::MAX_PER_SET <= (u16::MAX / 4)) as usize) - 1] =
  [(); _];

/// Update a validator's allocation by setting it to `amount`.
///
/// The purpose of this function is to ensure
/// [`AllocationsStorage::Allocations`] remains exactly synchronized with
/// [`AllocationsStorage::SortedAllocations`].
///
/// This returns the validator's prior allocation.
fn update_allocation<Storage: AllocationsStorage>(
  network: NetworkId,
  key: SeraiAddress,
  amount: Amount,
) -> Option<Amount> {
  // Remove their existing allocation, if one exists
  let prior = Storage::Allocations::take((network, key));
  if let Some(amount) = prior {
    Storage::SortedAllocations::remove(SortedAllocationsKey::new(network, key, amount));
  }
  // If we're setting a non-zero allocation, add it to the maps
  if amount.0 != 0 {
    Storage::Allocations::set((network, key), Some(amount));
    Storage::SortedAllocations::set(SortedAllocationsKey::new(network, key, amount), Some(()));
  }
  prior
}

/// Calculate the expected key shares for a network, per the current allocations.
///
/// This assumes that the selected validators will be the validators with the most stake allocated.
/// This will perform a linear (bounded) iteration over the greatest allocations, calculating the
/// corresponding amount of key shares per the current list. It has no insight into any greater
/// selection logic or caveats.
///
/// This uses the passed `allocation_per_key_share`, not the value in the storage, which allows
/// tearing. It is the caller's responsibility to ensure the correctness of the argument given
/// here. This decision was made as:
///
/// 1) All callers had already read the value from storage, and we wanted to avoid a redundant read
///
/// 2) If this fetched the value from storage, this function would have to handle the edge case
///    there _isn't_ a value in storage (which the callers currently handle)
fn expected_key_shares<Storage: AllocationsStorage>(
  network: NetworkId,
  allocation_per_key_share: Amount,
) -> KeyShares {
  let mut total_key_shares = 0;
  for (_, amount) in Storage::iter_allocations(network, allocation_per_key_share) {
    // `_MAX_PER_SET_IS_IN_RANGE` ensures we can sum any two `KeyShares` without issue
    // If the result is no longer valid as a `KeyShares`, we `break`
    total_key_shares += u16::from(KeyShares::from_allocation(amount, allocation_per_key_share));
    if total_key_shares >= KeyShares::MAX_PER_SET {
      break;
    }
  }
  KeyShares::saturating_from(total_key_shares)
}

/// Check if the validator with the most allocated for this network may be faulty without causing a
/// halt.
///
/// This assumes that the selected validators will be the validators with the most stake allocated.
/// It has no insight into any greater selection logic or caveats.
///
/// This uses the passed `allocation_per_key_share`, instead of reading it from storage, and
/// the passed `expected_key_shares`, instead of itself calling the `expected_key_shares` function.
/// This is done so the caller is responsible for ensuring there _is_ an `allocation_per_key_share`
/// defined and for performance reasons. Similar reasoning is documented in `expected_key_shares`'s
/// docstring.
fn currently_tolerates_single_point_of_failure<Storage: AllocationsStorage>(
  network: NetworkId,
  allocation_per_key_share: Amount,
  expected_key_shares: KeyShares,
) -> bool {
  if let Some(greatest_allocation) =
    Storage::iter_allocations(network, allocation_per_key_share).next()
  {
    let (_key, amount) = greatest_allocation;
    let key_shares = KeyShares::from_allocation(amount, allocation_per_key_share);
    ((3 * u16::from(key_shares)) + 1) <= u16::from(expected_key_shares)
  } else {
    // If there are no validators, then this doesn't currently tolerate a validator failing
    false
  }
}

impl<Storage: AllocationsStorage> Allocations for Storage {
  fn allocation(network: NetworkId, key: SeraiAddress) -> Option<Amount> {
    Storage::Allocations::get((network, key))
  }

  fn iter_allocations(
    network: impl Into<NetworkId>,
    minimum_allocation: Amount,
  ) -> impl Iterator<Item = (SeraiAddress, Amount)> {
    let network = network.into();

    let storage_prefix = Storage::SortedAllocations::final_prefix().to_vec();
    /*
      We want to iterate over the sorted allocations for this network specifically. We don't place
      this in the explicit prefix however as we want to decode the entire key but `PrefixIterator`
      will strip the prefix.

      This makes it our responsibility to check we don't begin iterating another network's
      allocations.
    */
    let mut last_key = storage_prefix.clone();
    last_key.extend(&network.encode());
    // Decode the read keys into `(validator, amount)` tuples
    frame_support::storage::PrefixIterator::<_, ()>::new(
      storage_prefix.clone(),
      last_key,
      |mut key, _value| SortedAllocationsKey::decode_all(&mut key),
    )
    // Filter by the network, specified minimum allocation
    .filter_map(move |key| {
      let amount = key.amount();
      ((key.network() == network) && (amount >= minimum_allocation))
        .then_some((key.validator(), amount))
    })
  }

  fn increase_allocation_without_updating_other_contexts(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
    reward: bool,
  ) -> Result<(), AllocationError> {
    // This is how we enforce the invariant every selected validator has the corresponding keys
    if !Self::has_necessary_auxiliary_keys(validator, network) {
      Err(AllocationError::MissingAuxiliaryKeys)?;
    }

    let old_allocation = Self::allocation(network, validator).unwrap_or(Amount(0));
    // As the supply fits in an `Amount`, this is safe so long as this allocation is valid
    let new_allocation = (old_allocation + amount).unwrap();

    if !reward {
      let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) else {
        Err(AllocationError::NoAllocationPerKeyShareSet)?
      };

      // As this will not be eligible for selection (under current parameters), reject it
      if new_allocation < allocation_per_key_share {
        Err(AllocationError::AllocationLessThanKeyShare)?;
      }

      let new_key_shares = KeyShares::from_allocation(new_allocation, allocation_per_key_share);

      // If this would guarantee this validator will be a single point of failure, error
      {
        let required_n_for_f_of_this_validator = (3 * u16::from(new_key_shares)) + 1;
        if required_n_for_f_of_this_validator > KeyShares::MAX_PER_SET {
          // This may _guarantee_ (not _introduce_) a single-point of failure, but this is fine
          Err(AllocationError::IntroducesSinglePointOfFailure)?;
        }
      }

      /*
        If the validator set has a single point of failure, the following does nothing. If the
        validator set has decentralized and doesn't have a single point of failure, the following
        will ensure this allocation doesn't create a single point of failure.
      */
      {
        // Check the validator set's current expected key shares
        let expected_key_shares = expected_key_shares::<Self>(network, allocation_per_key_share);

        // If the set currently tolerates the fault of any single validator, don't let that change
        if currently_tolerates_single_point_of_failure::<Self>(
          network,
          allocation_per_key_share,
          expected_key_shares,
        ) {
          let old_key_shares = KeyShares::from_allocation(old_allocation, allocation_per_key_share);
          /*
            Update the amount of expected key shares per the key shares added.

            If the set isn't at the limit of its key shares, than this validator will always be
            selected (as selection occurs until the limit) and these key shares will be considered.
            If the set is at the limit, it will remain at the limit for as long the amount of key
            shares held by validators which may be selected solely increases.

            While this may add the validator's new key shares when they won't be selected, that
            will only be a concern if the set is at its limit, in which case this calculation will
            still yield the limit as the expected amount of key shares (the correct answer).
          */
          let expected_key_shares = KeyShares::saturating_from(
            u16::from(expected_key_shares) +
              (u16::from(new_key_shares) - u16::from(old_key_shares)),
          );
          /*
           If the new key shares exceeds the fault tolerance, don't allow the allocation.

           This doesn't check the validator with the most key shares passes this check, as we
           already did that when we decided to ensure that property continues to hold true.
           Either:

           1) The validator with the most key shares keeps their position and their value, meaning
              this check is pointless.

           2) The current validator will _become_ the validator with the most key shares, meaning
              we need to check the _current validator_ will satisfy this check after the increase.

           For simplicity's sake, we model the latter condition without dedicating a branch to if
           we have to do this check at all.
          */
          if ((3 * u16::from(new_key_shares)) + 1) > u16::from(expected_key_shares) {
            Err(AllocationError::IntroducesSinglePointOfFailure)?;
          }
        }
      }
    }

    update_allocation::<Self>(network, validator, new_allocation);

    Ok(())
  }

  fn decrease_allocation_without_updating_other_contexts(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> Result<(), DeallocationError> {
    let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) else {
      Err(DeallocationError::NoAllocationPerKeyShareSet)?
    };

    let existing_allocation = Self::allocation(network, validator).unwrap_or(Amount(0));
    let new_allocation =
      (existing_allocation - amount).ok_or(DeallocationError::NotEnoughAllocated)?;
    if (new_allocation != Amount(0)) && (new_allocation < allocation_per_key_share) {
      Err(DeallocationError::RemainingAllocationLessThanKeyShare)?;
    }

    {
      /*
        We calculate the expected amount of stake, key shares _after_ this update occurs, along
        with the greatest amount of key shares held by a single validator _after_ this update
        occurs.

        Unfortunately, we do have to re-calculate this linearly (where as
        `increase_allocation_without_updating_other_contexts` solely calculates regarding the
        delta) due to:

        - The validator with the most key shares potentially changing, if this validator had the
          most key shares.

        - The amount of expected key shares potentially decreasing, if the validator set is not at
          its limit even after this decrease occurs.

        We could do a simpler calculation for the special case this validator did not have the most
        key shares (fixing that variable) _and_ we know the validator set was _not_ at its limit
        (letting us calculate the new amount of expected key shares without checking if more
        validators exist to replace these key shares upon the next selection). As we'd still have
        to do the following calculation for the general/worst case, and it covers every case, the
        complexity of the optimization isn't preferable.

        The following block is effectively an inline of `expected_key_shares`, substituting this
        validator's amount to what it _would be_, while also calculating:
          - The _new_ greatest amount of key shares.
          - The _new_ amount of stake the selected validators would have.
      */
      let mut expected_key_shares_for_current_state = 0u16;
      let mut would_be_selected = false;
      let mut expected_stake = 0;
      let mut expected_key_shares = 0;
      let mut most_key_shares = 0;
      for (this_validator, amount) in Storage::iter_allocations(network, allocation_per_key_share) {
        /*
          The expected amount of key shares for the current state.

          This should be equal to an invocation of the `expected_key_shares` function, with the
          proper arguments. The calculation is just inlined here for performance reasons.

          Generally, we would use a regular addition where we `break` immediately after it becomes
          unrepresentable as `KeyShares`. In this loop, we `break` when `expected_key_shares`
          becomes unrepresentable as `KeyShares`, which will happen when when this value would
          cause a `break` or after, but never before. That makes this value accurate but at risk of
          overflow, hence the use of saturating arithmetic.
        */
        expected_key_shares_for_current_state = expected_key_shares_for_current_state
          .saturating_add(u16::from(KeyShares::from_allocation(amount, allocation_per_key_share)));

        // If this is the validator which would be updated, substitute their amount
        let amount = if this_validator == validator {
          would_be_selected = true;
          new_allocation
        } else {
          amount
        };
        expected_stake += amount.0;

        let this_validator_key_shares =
          u16::from(KeyShares::from_allocation(amount, allocation_per_key_share));

        expected_key_shares += this_validator_key_shares;
        // This will either be set on the first or second iteration of this loop, as this is sorted
        // other than for how the current validator's position may change with the deallocation
        most_key_shares = most_key_shares.max(this_validator_key_shares);

        if expected_key_shares >= KeyShares::MAX_PER_SET {
          break;
        }
      }
      let expected_key_shares_for_current_state =
        KeyShares::saturating_from(expected_key_shares_for_current_state);
      debug_assert_eq!(
        expected_key_shares_for_current_state,
        crate::allocations::expected_key_shares::<Self>(network, allocation_per_key_share)
      );
      let expected_key_shares = KeyShares::saturating_from(expected_key_shares);

      // If the set currently tolerates the fault of any single validator, don't let that change
      if currently_tolerates_single_point_of_failure::<Self>(
        network,
        allocation_per_key_share,
        expected_key_shares_for_current_state,
      ) && (((3 * most_key_shares) + 1) > u16::from(expected_key_shares))
      {
        Err(DeallocationError::IntroducesSinglePointOfFailure)?;
      }

      // If this set is expected to have economic security, check if this would cause the set to
      // drop below our target amount of stake to be considered secure
      match network {
        NetworkId::Serai => {}
        NetworkId::External(network) => {
          if would_be_selected &&
            <Storage::Config as Config>::EconomicSecurity::achieved_economic_security(network) &&
            ((Amount(expected_stake) - amount) <
              Some(crate::Pallet::<Storage::Config>::network_stake_requirement(network)))
          {
            Err(DeallocationError::EconomicSecurity)?;
          }
        }
      }
    }

    // Finally, we check this isn't pre-economic security
    if ExternalNetworkId::all().any(|network| {
      !<Storage::Config as Config>::EconomicSecurity::achieved_economic_security(network)
    }) {
      Err(DeallocationError::EconomicSecurity)?;
    }

    update_allocation::<Self>(network, validator, new_allocation);

    Ok(())
  }

  fn drain_allocation(network: NetworkId, validator: SeraiAddress) -> Option<Amount> {
    update_allocation::<Self>(network, validator, Amount(0))
  }
}

#[cfg(test)]
mod mock {
  use frame_support::{pallet_prelude::*, traits::StorageInstance};
  use serai_abi::primitives::{network_id::NetworkId, balance::Amount};
  use super::{AllocationsKey, SortedAllocationsKey};

  pub struct PerKeyShare;
  impl StorageInstance for PerKeyShare {
    fn pallet_prefix() -> &'static str {
      "Allocations"
    }

    const STORAGE_PREFIX: &'static str = "Storage::AllocationPerKeyShare";
  }
  type AllocationPerKeyShareMap = StorageMap<PerKeyShare, Identity, NetworkId, Amount, OptionQuery>;

  pub struct Storage;
  impl StorageInstance for Storage {
    fn pallet_prefix() -> &'static str {
      "Allocations"
    }

    const STORAGE_PREFIX: &'static str = "Storage::Allocations";
  }
  type AllocationsMap = StorageMap<Storage, Blake2_128Concat, AllocationsKey, Amount, OptionQuery>;

  pub struct StorageSorted;
  impl StorageInstance for StorageSorted {
    fn pallet_prefix() -> &'static str {
      "Allocations"
    }

    const STORAGE_PREFIX: &'static str = "Storage::SortedAllocations";
  }
  type SortedAllocationsMap =
    StorageMap<StorageSorted, Identity, SortedAllocationsKey, (), OptionQuery>;

  impl super::AllocationsStorage for crate::MockStorage {
    type AllocationPerKeyShare = AllocationPerKeyShareMap;
    type Allocations = AllocationsMap;
    type SortedAllocations = SortedAllocationsMap;
  }
}

#[test]
fn test_get_iter_update_allocations() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    let prior_network = NetworkId::deserialize_reader(&mut [0].as_slice()).unwrap();
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();
    let following_network = NetworkId::deserialize_reader(&mut [2].as_slice()).unwrap();

    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(prior_network, Amount(1));
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(network, Amount(1));
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
      following_network,
      Amount(1),
    );

    // Create allocations
    let rand_allocation = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      let key = SeraiAddress(key);
      let amount = Amount(OsRng.next_u64());
      (key, amount)
    };
    const ALLOCATIONS: usize = 100;
    let mut allocations = vec![];
    for _ in 0 .. ALLOCATIONS {
      let (key, amount) = rand_allocation();
      allocations.push((key, amount));
      assert_eq!(update_allocation::<MockStorage>(network, key, amount), None);
      assert_eq!(MockStorage::allocation(network, key), Some(amount));
    }
    // Sort them from highest amount to lowest
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();

    // Set allocations for the previous and next network, by byte, to ensure the map isn't solely
    // these allocations. This ensures we don't read from another network accidentally
    {
      let (key, amount) = rand_allocation();
      assert_eq!(update_allocation::<MockStorage>(prior_network, key, amount), None);
      assert_eq!(update_allocation::<MockStorage>(following_network, key, amount), None);
    }

    // Check the iterator works
    {
      let mut a = MockStorage::iter_allocations(network, Amount(0));
      let mut b = allocations.clone().into_iter();
      for _ in 0 .. allocations.len() {
        let next = a.next().unwrap();
        assert_eq!(b.next().unwrap(), next);

        let (validator, amount) = next;
        assert_eq!(MockStorage::allocation(network, validator), Some(amount));
      }
      assert!(a.next().is_none());
      assert!(b.next().is_none());
    }

    // Check the minimum works
    {
      assert_eq!(
        MockStorage::iter_allocations(network, allocations[0].1).next(),
        Some(allocations[0])
      );
      assert_eq!(
        MockStorage::iter_allocations(
          network,
          // Fails with probability ~1/2**57
          (allocations[0].1 + Amount(1)).expect("1/2**57")
        )
        .next(),
        None,
      );
    }

    // Check updating an allocation works
    for _ in 0 .. (allocations.len() / 2) {
      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let i = (OsRng.next_u64() as usize) % allocations.len();
      if (OsRng.next_u64() & 1) == 1 {
        let new_amount = Amount(OsRng.next_u64());
        assert_eq!(
          update_allocation::<MockStorage>(network, allocations[i].0, new_amount),
          Some(allocations[i].1)
        );
        allocations[i].1 = new_amount;
      } else {
        assert_eq!(
          update_allocation::<MockStorage>(network, allocations[i].0, Amount(0)),
          Some(allocations[i].1)
        );
        allocations.swap_remove(i);
      }
    }
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();
    {
      let mut a = MockStorage::iter_allocations(network, Amount(0));
      let mut b = allocations.clone().into_iter();
      for _ in 0 .. allocations.len() {
        let next = a.next().unwrap();
        assert_eq!(b.next().unwrap(), next);

        let (validator, amount) = next;
        assert_eq!(MockStorage::allocation(network, validator), Some(amount));
      }
      assert!(a.next().is_none());
      assert!(b.next().is_none());
    }
  });
}
