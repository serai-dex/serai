use sp_core::{Encode, Decode, ConstU32, sr25519::Public, bounded::BoundedVec};

use serai_primitives::{
  constants::{MAX_KEY_SHARES_PER_SET, MAX_KEY_SHARES_PER_SET_U32},
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{Session, ValidatorSet, amortize_excess_key_shares},
};

use frame_support::storage::{StorageValue, StorageMap, StorageDoubleMap, StoragePrefixedMap};

use crate::{embedded_elliptic_curve_keys::EmbeddedEllipticCurveKeys, allocations::Allocations};

/// The list of genesis validators.
pub(crate) type GenesisValidators = BoundedVec<Public, ConstU32<{ MAX_KEY_SHARES_PER_SET_U32 }>>;

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

  /// The selected validators for a set.
  ///
  /// This MUST be instantiated with a map using `Identity` for its hasher.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  // The value is how many key shares the validator has.
  type SelectedValidators: StorageMap<SelectedValidatorsKey, u64, Query = Option<u64>>
    + StoragePrefixedMap<u64>;

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

fn selected_validators<Storage: StoragePrefixedMap<u64>>(
  set: ValidatorSet,
) -> impl Iterator<Item = (Public, u64)> {
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
        u64::decode(&mut key_shares).unwrap(),
      ))
    },
  )
}

fn clear_selected_validators<Storage: StoragePrefixedMap<u64>>(set: ValidatorSet) {
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
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool);

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
}

impl<Storage: SessionsStorage> Sessions for Storage {
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool) {
    // If we haven't rotated to the latest decided session, return
    // This prevents us from deciding session #n+2 when we haven't even started #n+1
    let current_session = Storage::CurrentSession::get(network);
    match (current_session, Storage::LatestDecidedSession::get(network)) {
      (Some(current), Some(latest)) => {
        if current == latest {
          // If the latest decided session is current, we can decide the next session
        } else {
          // If we already have a pending session, don't spawn a new one
          return;
        }
      }
      (Some(current), None) => unreachable!("current session but never decided a session"),
      // If we decided our first session, but didn't start it, don't decide another session
      (None, Some(latest)) => return,
      (None, None) => {
        // If we've never started a session, we can decide the first session
      }
    }

    let mut selected_validators = Vec::with_capacity(usize::from(MAX_KEY_SHARES_PER_SET / 2));
    let mut total_key_shares = 0;
    if let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) {
      for (validator, amount) in Self::iter_allocations(network, allocation_per_key_share) {
        // If this allocation is absurd, causing this to not fit within a u16, bound to the max
        let key_shares = amount.0 / allocation_per_key_share.0;
        selected_validators.push((validator, key_shares));
        // We're tracking key shares as a u64 yet the max allowed is a u16, so this won't overflow
        total_key_shares += key_shares;
        if total_key_shares >= u64::from(MAX_KEY_SHARES_PER_SET) {
          break;
        }
      }
    }

    // Perform amortization if we've exceeded the maximum amount of key shares
    // This is guaranteed not to cause any validators have zero key shares as we'd only be over if
    // the last-added (worst) validator had multiple key shares, meaning everyone has more shares
    // than we'll amortize here
    amortize_excess_key_shares(selected_validators.as_mut_slice());

    if include_genesis_validators {
      let mut genesis_validators = Storage::GenesisValidators::get()
        .expect("genesis validators wasn't set")
        .into_iter()
        .map(|validator| (validator, 1))
        .collect::<Vec<_>>();
      let genesis_validator_key_shares = u64::try_from(genesis_validators.len()).unwrap();
      while (total_key_shares + genesis_validator_key_shares) > u64::from(MAX_KEY_SHARES_PER_SET) {
        let (_key, key_shares) = selected_validators.pop().unwrap();
        total_key_shares -= key_shares;
      }
      selected_validators.append(&mut genesis_validators);
      total_key_shares += genesis_validator_key_shares;
    }

    // We kept this accurate but don't actually further read from it
    let _ = total_key_shares;

    let latest_decided_session = Storage::LatestDecidedSession::mutate(network, |session| {
      let next_session = session.map(|session| Session(session.0 + 1)).unwrap_or(Session(0));
      *session = Some(next_session);
      next_session
    });

    let latest_decided_set = ValidatorSet { network, session: latest_decided_session };
    for (key, key_shares) in selected_validators {
      Storage::SelectedValidators::insert(
        selected_validators_key(latest_decided_set, key),
        key_shares,
      );
    }
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
      clear_selected_validators::<Storage::SelectedValidators>(ValidatorSet {
        network,
        session: historic_session,
      });
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

    /*
      If the validator set has a single point of failure, the following does nothing. If the
      validator set has decentralized and doesn't have a single point of failure, the following
      will ensure this allocation doesn't create a single point of failure.
    */
    {
      // Check the validator set's current expected key shares
      let expected_key_shares = Self::expected_key_shares(network, allocation_per_key_share);
      // Check if the top validator in this set may be faulty under this f
      let top_validator_may_be_faulty = if let Some(top_validator) =
        Self::iter_allocations(network, allocation_per_key_share).next()
      {
        let (_key, amount) = top_validator;
        let key_shares = amount.0 / allocation_per_key_share.0;
        key_shares <= (expected_key_shares / 3)
      } else {
        // If there are no validators, we claim the top validator may not be faulty so the
        // following check doesn't run
        false
      };
      if top_validator_may_be_faulty {
        let old_key_shares = old_allocation.0 / allocation_per_key_share.0;
        let new_key_shares = new_allocation.0 / allocation_per_key_share.0;
        // Update the amount of expected key shares per the key shares added
        let expected_key_shares = (expected_key_shares + (new_key_shares - old_key_shares))
          .min(u64::from(MAX_KEY_SHARES_PER_SET));
        // If the new key shares exceeds the fault tolerance, don't allow the allocation
        if new_key_shares > (expected_key_shares / 3) {
          Err(AllocationError::IntroducesSinglePointOfFailure)?
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
}
