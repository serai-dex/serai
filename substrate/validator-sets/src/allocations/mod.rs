//! `Allocations` is a simple abstraction over a pair of `StorageMap`s which ensure they remain
//! synchronized and enable iterating over validators by the amount they've allocated. This
//! iteration is used to select validators for new sessions.

use scale::{Encode as _, DecodeAll as _};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    network_id::{ExternalNetworkId, NetworkId},
    balance::Amount,
    validator_sets::KeyShares,
  },
  economic_security::EconomicSecurity,
};

use frame_support::storage::{StorageMap, StoragePrefixedMap};

mod sorted_key;
pub(crate) use sorted_key::*;

mod delayed;
#[rustfmt::skip]
pub(crate) use delayed::{DelayedDeallocationsStorage, DelayedDeallocationError, DelayedDeallocations};

use crate::auxiliary_keys::AuxiliaryKeys as _;

#[cfg(test)]
mod tests;

/// The key to use for the allocations map.
pub(crate) type AllocationsKey = (NetworkId, SeraiAddress);

/// A `trait` to access networks' stake requirements via.
///
/// This should be `serai_validator_sets_pallet::network_stake_requirement`, which requires being
/// parameterized by a `serai_coins_pallet::Config` and `EconomicSecurity`. Explicitly declaring
/// this trait here allows the tests for this abstraction to not define such a complete runtime.
pub(crate) trait NetworkStakeRequirement {
  fn requirement(network: ExternalNetworkId) -> Amount;
}
impl<T: crate::Config> NetworkStakeRequirement for crate::Pallet<T> {
  fn requirement(network: ExternalNetworkId) -> Amount {
    crate::network_stake_requirement::<T, T::EconomicSecurity>(network)
  }
}
#[cfg(test)]
impl NetworkStakeRequirement for () {
  fn requirement(_network: ExternalNetworkId) -> Amount {
    Amount(0)
  }
}

/// An error when allocating.
#[derive(
  Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
#[cfg_attr(test, derive(PartialEq, Eq))]
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
#[cfg_attr(test, derive(PartialEq, Eq))]
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
  /// The evaluator of economic security.
  type EconomicSecurity: EconomicSecurity;
  /// A getter for the network's required amount of allocated stake.
  type NetworkStakeRequirement: NetworkStakeRequirement;

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

  /// A map storing the sum of allocations for a network.
  ///
  /// This is to be exclusively written to by `Allocations` but may be read by the rest of the
  /// pallet.
  ///
  /// Internally to the Serai protocol, this is used pre-Economic Security to evaluate how much
  /// stake has been allocated in order to then calculate the distance to economic security.
  type SumAllocations: StorageMap<NetworkId, Amount, Query = Amount>;
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
  /// share (when not a reward), it does not ensure the storage will only contain validators which
  /// qualify for at least one key share. This is due to the potential for `AllocationPerKeyShare`
  /// to be independently updated, potentially increasing the value _past_ what some validators
  /// have already allocated, among other things. It solely applies the minimum bound to prevent
  /// trivial entries from being written to storage.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for the allocation with regards to the `Allocations` abstraction present here. This function
  /// may panic if the transfer has not occured and may be invalid when it occurs.
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

  /// Drain a validator's current allocation.
  ///
  /// This is intended to be called in response to a fatal slash. It will set the validator's
  /// allocation to `0` regardless of the context.
  ///
  /// This function will return the `Amount` drained.
  fn drain_allocation(validator: SeraiAddress, network: NetworkId) -> Option<Amount>;
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
/// [`AllocationsStorage::SortedAllocations`] and
/// [`AllocationsStorage::SumAllocations`].
///
/// This returns the validator's prior allocation. This function has undefined behavior if the new
/// allocation is not valid.
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
  // Update the sum of allocations
  {
    let prior = prior.unwrap_or(Amount(0));
    if prior < amount {
      let increase = (amount - prior).expect("couldn't subtract smaller amount from larger amount");
      Storage::SumAllocations::mutate(network, |value| {
        *value =
          (*value + increase).expect("sum of allocations exceeded `Amount`, meaning SRI supply has")
      });
    } else {
      let decrease = (prior - amount).expect("couldn't subtract smaller amount from larger amount");
      Storage::SumAllocations::mutate(network, |value| {
        *value = (*value - decrease).expect("sum of allocations was less than a present allocation")
      });
    }
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
            Storage::EconomicSecurity::achieved_economic_security(network) &&
            ((Amount(expected_stake) - amount) <
              Some(Storage::NetworkStakeRequirement::requirement(network)))
          {
            Err(DeallocationError::EconomicSecurity)?;
          }
        }
      }
    }

    // Finally, we check this isn't pre-economic security
    if ExternalNetworkId::all()
      .any(|network| !Storage::EconomicSecurity::achieved_economic_security(network))
    {
      Err(DeallocationError::EconomicSecurity)?;
    }

    update_allocation::<Self>(network, validator, new_allocation);

    Ok(())
  }

  fn drain_allocation(validator: SeraiAddress, network: NetworkId) -> Option<Amount> {
    update_allocation::<Self>(network, validator, Amount(0))
  }
}

#[cfg(test)]
mod mock {
  use frame_support::{pallet_prelude::*, traits::StorageInstance};
  use serai_abi::primitives::{
    network_id::{ExternalNetworkId, NetworkId},
    coin::{ExternalCoin, Coin},
    balance::{Amount, ExternalBalance},
  };
  use super::{AllocationsKey, SortedAllocationsKey};
  use crate::MockStorage;

  pub const STAKE_REQUIREMENT: Amount = Amount(30_000 * 10u64.pow(Coin::Serai.decimals()));

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

  pub struct StorageSum;
  impl StorageInstance for StorageSum {
    fn pallet_prefix() -> &'static str {
      "Allocations"
    }

    const STORAGE_PREFIX: &'static str = "Storage::SumAllocations";
  }
  type SumAllocations = StorageMap<StorageSum, Identity, NetworkId, Amount, ValueQuery>;

  impl serai_abi::economic_security::EconomicSecurity for MockStorage {
    fn achieved_economic_security(network: ExternalNetworkId) -> bool {
      SumAllocations::get(network) >= STAKE_REQUIREMENT
    }
    fn sri_value(balance: ExternalBalance) -> Amount {
      match balance.coin {
        ExternalCoin::Bitcoin => (balance.amount * Amount(10)).unwrap(),
        ExternalCoin::Ether => (balance.amount * Amount(5)).unwrap(),
        ExternalCoin::Monero => (balance.amount * Amount(3)).unwrap(),
        ExternalCoin::Dai => (balance.amount * Amount(2)).unwrap(),
      }
    }
  }

  impl super::AllocationsStorage for crate::MockStorage {
    type EconomicSecurity = MockStorage;
    type NetworkStakeRequirement = ();
    type AllocationPerKeyShare = AllocationPerKeyShareMap;
    type Allocations = AllocationsMap;
    type SortedAllocations = SortedAllocationsMap;
    type SumAllocations = SumAllocations;
  }
}
