use alloc::vec::Vec;
use sp_core::{Encode, Decode, ConstU32, sr25519::Public, bounded::BoundedVec};

use serai_abi::primitives::{
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{KeyShares as KeySharesStruct, Session, ValidatorSet},
};

use frame_support::storage::{StorageValue, StorageMap, StorageDoubleMap, StoragePrefixedMap};

use crate::{embedded_elliptic_curve_keys::EmbeddedEllipticCurveKeys, allocations::Allocations};

/// The list of genesis validators.
pub(crate) type GenesisValidators =
  BoundedVec<Public, ConstU32<{ KeySharesStruct::MAX_PER_SET_U32 }>>;

/// The key for the SelectedValidators map.
pub(crate) type SelectedValidatorsKey = (ValidatorSet, [u8; 16], Public);

pub(crate) trait SessionsStorage: EmbeddedEllipticCurveKeys + Allocations {
  /// The genesis validators
  ///
  /// The usage of is shared with the rest of the pallet. `Sessions` only reads it.
  type GenesisValidators: StorageValue<GenesisValidators, Query = Option<GenesisValidators>>;

  /// The allocation required for a key share.
  ///
  /// The usage of is shared with the rest of the pallet. `Sessions` only reads it.
  type AllocationPerKeyShare: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// The current session.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type CurrentSession: StorageMap<NetworkId, Session, Query = Option<Session>>;

  /// The latest session which has been decided.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type LatestDecidedSession: StorageMap<NetworkId, Session, Query = Option<Session>>;

  /// The amount of key shares a validator set has.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type KeyShares: StorageMap<ValidatorSet, KeySharesStruct, Query = Option<KeySharesStruct>>;

  /// The selected validators for a set.
  ///
  /// This MUST be instantiated with a map using `Identity` for its hasher.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  // The value is how many key shares the validator has.
  #[rustfmt::skip]
  type SelectedValidators: StorageMap<
    SelectedValidatorsKey,
    KeySharesStruct,
    Query = Option<KeySharesStruct>
  > + StoragePrefixedMap<KeySharesStruct>;

  /// The total allocated stake for a network.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type TotalAllocatedStake: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// The delayed deallocations.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type DelayedDeallocations: StorageDoubleMap<Public, Session, Amount, Query = Option<Amount>>;
}

/// The storage key for the SelectedValidators map.
fn selected_validators_key(set: ValidatorSet, key: Public) -> SelectedValidatorsKey {
  let hash = sp_io::hashing::blake2_128(&(set, key).encode());
  (set, hash, key)
}

fn selected_validators<Storage: StoragePrefixedMap<KeySharesStruct>>(
  set: ValidatorSet,
) -> impl Iterator<Item = (Public, KeySharesStruct)> {
  let mut prefix = Storage::final_prefix().to_vec();
  prefix.extend(&set.encode());
  frame_support::storage::PrefixIterator::<_, ()>::new(
    prefix.clone(),
    prefix,
    |key, mut key_shares| {
      Ok((
        // Recover the validator's key from the storage key
        <[u8; 32]>::try_from(&key[(key.len() - 32) ..]).unwrap().into(),
        // Decode the key shares from the value
        KeySharesStruct::decode(&mut key_shares).unwrap(),
      ))
    },
  )
}

fn clear_selected_validators<Storage: StoragePrefixedMap<KeySharesStruct>>(set: ValidatorSet) {
  let mut prefix = Storage::final_prefix().to_vec();
  prefix.extend(&set.encode());
  assert!(matches!(
    sp_io::storage::clear_prefix(&prefix, None),
    sp_io::KillStorageResult::AllRemoved(_)
  ));
}

/// An error when allocating.
#[derive(
  scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
pub enum AllocationError {
  /// The validator set didn't define an allocation requirement for a key share.
  NoAllocationPerKeyShareSet,
  /// Validator is missing embedded elliptic curve keys.
  MissingEmbeddedEllipticCurveKeys,
  /// The allocation is less than the key share.
  AllocationLessThanKeyShare,
  /// This allocation would introduce a single point of failure.
  IntroducesSinglePointOfFailure,
}

pub(crate) enum DeallocationTimeline {
  Immediate,
  Delayed { unlocks_at: Session },
}

/// An error when deallocating.
#[derive(
  scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
pub enum DeallocationError {
  /// The validator set didn't define an allocation requirement for a key share.
  NoAllocationPerKeyShareSet,
  /// Not enough was allocated to enable this amount to be deallocated.
  NotEnoughAllocated,
  /// The remaining allocation was non-zero and would be less than a key share.
  RemainingAllocationLessThanKeyShare,
  /// The delay has yet to be satisfied.
  DelayNotSatisfied,
  /// No delayed deallocation was present.
  NoDelayedDeallocation,
}

pub(crate) trait Sessions {
  /// Attempt to spawn a new session for the specified network.
  ///
  /// Validators will be selected by their allocations if `AllocationPerKeyShare` is set for this
  /// network. `include_genesis_validators` will cause genesis validators to be included *with
  /// greater priority than non-genesis validators*.
  ///
  /// Doesn't spawn the next session if the latest decided session has yet to start. This bounds
  /// the current session to be the latest decided session or the one prior.
  ///
  /// Returns `true` if the next session was decided. Returns `false` otherwise.
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool) -> bool;

  /// Have the latest-decided session accept the handover from the current set, if one exists.
  ///
  /// Every decided set must accept the handover to become current.
  ///
  /// May panic if the latest-decided session is already the current session, or if there was no
  /// latest-decided session.
  fn accept_handover(network: NetworkId);

  /// Increase a validator's allocation.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the book-keeping
  /// of it.
  fn increase_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
    block_reward: bool,
  ) -> Result<(), AllocationError>;

  /// Decrease a validator's allocation.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the book-keeping
  /// of it.
  fn decrease_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
  ) -> Result<DeallocationTimeline, DeallocationError>;

  /// Claim a delayed allocation.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the book-keeping
  /// of it.
  fn claim_delayed_deallocation(
    validator: Public,
    network: NetworkId,
    session: Session,
  ) -> Result<Amount, DeallocationError>;

  /// The currently active session for a network.
  fn current_session(network: NetworkId) -> Option<Session>;

  /// The latest decided session for a network.
  fn latest_decided_session(network: NetworkId) -> Option<Session>;

  /// The amount of key shares a validator has.
  ///
  /// Returns `None` for historic sessions which we no longer have the data for.
  fn key_shares(set: ValidatorSet) -> Option<KeySharesStruct>;

  /// If a validator is present within the specified validator set.
  ///
  /// This MAY return `false` for _any_ historic session, even if the validator _was_ present,
  fn in_validator_set(set: ValidatorSet, validator: Public) -> bool;

  /// The key shares possessed by a validator, within a validator set.
  ///
  /// This MAY return `None` for _any_ historic session, even if the validator _was_ present,
  fn key_shares_possessed_by_validator(
    set: ValidatorSet,
    validator: Public,
  ) -> Option<KeySharesStruct>;

  /// The stake for the current validator set.
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount>;

  /// The selected validators for a set.
  ///
  /// This will return an empty iterator if the validators have yet to be decided, or if the
  /// selected validators were cleared due to being historic.
  fn selected_validators(set: ValidatorSet) -> impl Iterator<Item = (Public, KeySharesStruct)>;

  /// The validators for the Serai network, in the form expected by BABE, GRANDPA.
  fn serai_validators(session: Session) -> Vec<(Public, Public)> {
    Self::selected_validators(ValidatorSet { network: NetworkId::Serai, session })
      .map(|(validator, _key_shares)| (validator, validator))
      .collect()
  }
}

impl<Storage: SessionsStorage> Sessions for Storage {
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool) -> bool {
    // If we haven't rotated to the latest decided session, return
    // This prevents us from deciding session #n+2 when we haven't even started #n+1
    let current_session = Storage::CurrentSession::get(network);
    match (current_session, Storage::LatestDecidedSession::get(network)) {
      (Some(current), Some(latest)) => {
        if current == latest {
          // If the latest decided session is current, we can decide the next session
        } else {
          // If we already have a pending session, don't spawn a new one
          return false;
        }
      }
      (Some(_current), None) => unreachable!("current session but never decided a session"),
      // If we decided our first session, but didn't start it, don't decide another session
      (None, Some(_latest)) => return false,
      (None, None) => {
        // If we've never started a session, we can decide the first session
      }
    }

    let mut selected_validators = Vec::with_capacity(usize::from(KeySharesStruct::MAX_PER_SET / 2));
    let mut total_key_shares = 0;
    if let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) {
      for (validator, amount) in Self::iter_allocations(network, allocation_per_key_share) {
        let key_shares = KeySharesStruct::from_allocation(amount, allocation_per_key_share);
        selected_validators.push((validator, key_shares));
        total_key_shares += key_shares.0;
        if total_key_shares >= KeySharesStruct::MAX_PER_SET {
          break;
        }
      }
    }

    // Perform amortization if we've exceeded the maximum amount of key shares
    {
      let new_len = KeySharesStruct::amortize_excess(selected_validators.as_mut_slice());
      selected_validators.truncate(new_len);
    }

    if include_genesis_validators {
      let mut genesis_validators = Storage::GenesisValidators::get()
        .expect("genesis validators wasn't set")
        .into_iter()
        .map(|validator| (validator, KeySharesStruct::ONE))
        .collect::<Vec<_>>();
      let genesis_validator_key_shares = u16::try_from(genesis_validators.len()).unwrap();
      total_key_shares += genesis_validator_key_shares;
      while total_key_shares > KeySharesStruct::MAX_PER_SET {
        let (_key, key_shares) = selected_validators.pop().unwrap();
        total_key_shares -= key_shares.0;
      }
      selected_validators.append(&mut genesis_validators);
    }

    let latest_decided_session = Storage::LatestDecidedSession::mutate(network, |session| {
      let next_session = session.map(|session| Session(session.0 + 1)).unwrap_or(Session(0));
      *session = Some(next_session);
      next_session
    });

    let latest_decided_set = ValidatorSet { network, session: latest_decided_session };
    Storage::KeyShares::insert(
      latest_decided_set,
      KeySharesStruct::try_from(total_key_shares).expect("amortization failure"),
    );
    for (key, key_shares) in selected_validators {
      Storage::SelectedValidators::insert(
        selected_validators_key(latest_decided_set, key),
        key_shares,
      );
    }

    true
  }

  fn accept_handover(network: NetworkId) {
    let current = {
      let current = Storage::CurrentSession::get(network);
      let latest_decided = Storage::LatestDecidedSession::get(network)
        .expect("accepting handover but never decided a session");
      assert_eq!(
        current,
        latest_decided.0.checked_sub(1).map(Session),
        "current session wasn't prior to latest-decided"
      );
      // Set the CurrentSession variable
      Storage::CurrentSession::set(network, Some(latest_decided));
      // Return `latest_decided` as `current` as it is now current
      latest_decided
    };

    let mut total_allocated_stake = Amount(0);
    for (key, _key_shares) in
      selected_validators::<Storage::SelectedValidators>(ValidatorSet { network, session: current })
    {
      // Safe so long as the SRI supply fits within a u64
      total_allocated_stake =
        (total_allocated_stake + Self::get_allocation(network, key).unwrap_or(Amount(0))).unwrap();
    }
    // Update the total allocated stake variable to the current session
    Storage::TotalAllocatedStake::set(network, Some(total_allocated_stake));

    // Clean-up the historic set's storage, if one exists
    if let Some(historic_session) = current.0.checked_sub(2).map(Session) {
      let historic_set = ValidatorSet { network, session: historic_session };
      Storage::KeyShares::remove(historic_set);
      clear_selected_validators::<Storage::SelectedValidators>(historic_set);
    }
  }

  fn increase_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
    block_reward: bool,
  ) -> Result<(), AllocationError> {
    let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) else {
      Err(AllocationError::NoAllocationPerKeyShareSet)?
    };

    if Self::still_needs_to_set_embedded_elliptic_curve_keys(network, validator) {
      Err(AllocationError::MissingEmbeddedEllipticCurveKeys)?;
    }

    let old_allocation = Self::get_allocation(network, validator).unwrap_or(Amount(0));
    // Safe so long as the SRI supply fits within a u64, per assumptions on how this is called
    let new_allocation = (old_allocation + amount).unwrap();
    // Always allow a block reward to be added
    if (!block_reward) && (new_allocation < allocation_per_key_share) {
      Err(AllocationError::AllocationLessThanKeyShare)?
    }

    {
      let new_key_shares =
        KeySharesStruct::from_allocation(new_allocation, allocation_per_key_share);

      // If this would guarantee this validator will be a single point of failure, error
      if ((3 * new_key_shares.0) + 1) > KeySharesStruct::MAX_PER_SET {
        Err(AllocationError::IntroducesSinglePointOfFailure)?;
      }

      /*
        If the validator set has a single point of failure, the following does nothing. If the
        validator set has decentralized and doesn't have a single point of failure, the following
        will ensure this allocation doesn't create a single point of failure.
      */
      {
        // Check the validator set's current expected key shares
        let expected_key_shares = Self::expected_key_shares(network, allocation_per_key_share);
        // Check if the top validator in this set may be faulty without causing a halt under this f
        let currently_tolerates_single_point_of_failure = if let Some(top_validator) =
          Self::iter_allocations(network, allocation_per_key_share).next()
        {
          let (_key, amount) = top_validator;
          let key_shares = KeySharesStruct::from_allocation(amount, allocation_per_key_share);
          key_shares.0 <= (expected_key_shares.0 / 3)
        } else {
          false
        };
        // If the set currently tolerates the fault of the top validator, don't let that change
        if currently_tolerates_single_point_of_failure {
          let old_key_shares =
            KeySharesStruct::from_allocation(old_allocation, allocation_per_key_share);
          // Update the amount of expected key shares per the key shares added
          let expected_key_shares = KeySharesStruct::saturating_from(
            expected_key_shares.0 + (new_key_shares.0 - old_key_shares.0),
          );
          // If the new key shares exceeds the fault tolerance, don't allow the allocation
          if new_key_shares.0 > (expected_key_shares.0 / 3) {
            Err(AllocationError::IntroducesSinglePointOfFailure)?;
          }
        }
      }
    }

    Self::set_allocation(network, validator, new_allocation);
    // If this validator is active, update `TotalAllocatedStake`
    if let Some(current) = Storage::CurrentSession::get(network) {
      if Storage::SelectedValidators::contains_key(selected_validators_key(
        ValidatorSet { network, session: current },
        validator,
      )) {
        Storage::TotalAllocatedStake::mutate(network, |existing| {
          Some(
            (existing.expect("current session but no total allocated stake set") + amount).unwrap(),
          )
        });
      }
    }

    Ok(())
  }

  fn decrease_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
  ) -> Result<DeallocationTimeline, DeallocationError> {
    /*
      Decrease the allocation.

      This doesn't affect the key shares, as that's immutable after creation, and doesn't affect
      affect the `TotalAllocatedStake` as the validator either isn't current or the deallocation
      will be queued *but is still considered allocated for this session*.

      When the next set is selected, and becomes current, `TotalAllocatedStake` will be updated
      per the allocations as-is.
    */
    {
      let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) else {
        Err(DeallocationError::NoAllocationPerKeyShareSet)?
      };

      let existing_allocation = Self::get_allocation(network, validator).unwrap_or(Amount(0));
      let new_allocation =
        (existing_allocation - amount).ok_or(DeallocationError::NotEnoughAllocated)?;
      if (new_allocation != Amount(0)) && (new_allocation < allocation_per_key_share) {
        Err(DeallocationError::RemainingAllocationLessThanKeyShare)?
      }

      Self::set_allocation(network, validator, new_allocation);
    }

    /*
      For a validator present in set #n, they should only be able to deallocate once set #n+2 is
      current. That means if set #n is malicious, and they rotate to a malicious set #n+1 with a
      reduced stake requirement, further handovers can be stopped during set #n+1 (along with
      stopping any pending deallocations).
    */
    {
      let check_presence = |session| {
        Storage::SelectedValidators::contains_key(selected_validators_key(
          ValidatorSet { network, session },
          validator,
        ))
      };
      // Find the latest set this validator was present in, which isn't historic
      let find_latest_session = || {
        // Check the latest decided session
        if let Some(latest) = Storage::LatestDecidedSession::get(network) {
          if check_presence(latest) {
            return Some(latest);
          }

          // If there was a latest decided session, but we weren't in it, check current
          if let Some(current) = Storage::CurrentSession::get(network) {
            if check_presence(current) {
              return Some(current);
            }
            // Finally, check the prior session, as we shouldn't be able to deallocate from a
            // session we were in solely because we weren't selected for further sessions
            if let Some(prior) = current.0.checked_sub(1).map(Session) {
              if check_presence(prior) {
                return Some(prior);
              }
            }
          }
        }
        None
      };
      if let Some(present) = find_latest_session() {
        // Because they were present in this session, determine the session this unlocks at
        let unlocks_at = Session(present.0 + 2);
        Storage::DelayedDeallocations::mutate(validator, unlocks_at, |delayed| {
          *delayed = Some((delayed.unwrap_or(Amount(0)) + amount).unwrap());
        });
        return Ok(DeallocationTimeline::Delayed { unlocks_at });
      }
    }

    // Because the network either doesn't have a current session, or this validator wasn't present,
    // immediately handle the deallocation
    Ok(DeallocationTimeline::Immediate)
  }

  fn claim_delayed_deallocation(
    validator: Public,
    network: NetworkId,
    session: Session,
  ) -> Result<Amount, DeallocationError> {
    if Storage::CurrentSession::get(network).map(|session| session.0) <
      Some(session).map(|session| session.0)
    {
      Err(DeallocationError::DelayNotSatisfied)?;
    }
    Storage::DelayedDeallocations::take(validator, session)
      .ok_or(DeallocationError::NoDelayedDeallocation)
  }

  fn current_session(network: NetworkId) -> Option<Session> {
    Storage::CurrentSession::get(network)
  }

  fn latest_decided_session(network: NetworkId) -> Option<Session> {
    Storage::LatestDecidedSession::get(network)
  }

  fn key_shares(set: ValidatorSet) -> Option<KeySharesStruct> {
    Storage::KeyShares::get(set)
  }

  fn in_validator_set(set: ValidatorSet, validator: Public) -> bool {
    Storage::SelectedValidators::contains_key(selected_validators_key(set, validator))
  }

  fn key_shares_possessed_by_validator(
    set: ValidatorSet,
    validator: Public,
  ) -> Option<KeySharesStruct> {
    Storage::SelectedValidators::get(selected_validators_key(set, validator))
  }

  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Storage::TotalAllocatedStake::get(network)
  }

  fn selected_validators(set: ValidatorSet) -> impl Iterator<Item = (Public, KeySharesStruct)> {
    selected_validators::<Storage::SelectedValidators>(set)
  }
}
