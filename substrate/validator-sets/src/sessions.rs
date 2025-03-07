use sp_core::{Encode, Decode, ConstU32, sr25519::Public, bounded::BoundedVec};

use serai_primitives::{
  constants::{MAX_KEY_SHARES_PER_SET, MAX_KEY_SHARES_PER_SET_U32},
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{Session, ValidatorSet, amortize_excess_key_shares},
};

use frame_support::storage::{StorageValue, StorageMap, StoragePrefixedMap};

use crate::allocations::*;

/// The list of genesis validators.
type GenesisValidators = BoundedVec<Public, ConstU32<{ MAX_KEY_SHARES_PER_SET_U32 }>>;

/// The key for the SelectedValidators map.
type SelectedValidatorsKey = (ValidatorSet, [u8; 16], Public);

pub(crate) trait SessionsStorage: AllocationsStorage {
  /// The genesis validators
  ///
  /// The usage of is shared with the rest of the pallet. `Sessions` only reads it.
  type GenesisValidators: StorageValue<GenesisValidators, Query = GenesisValidators>;

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
  type SelectedValidators: StorageMap<SelectedValidatorsKey, u64> + StoragePrefixedMap<()>;

  /// The total allocated stake for a network.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type TotalAllocatedStake: StorageMap<NetworkId, Amount, Query = Option<Amount>>;
}

/// The storage key for the SelectedValidators map.
fn selected_validators_key(set: ValidatorSet, key: Public) -> SelectedValidatorsKey {
  let hash = sp_io::hashing::blake2_128(&(set, key).encode());
  (set, hash, key)
}

fn selected_validators<Storage: StorageMap<SelectedValidatorsKey, u64> + StoragePrefixedMap<()>>(
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

fn clear_selected_validators<
  Storage: StorageMap<SelectedValidatorsKey, u64> + StoragePrefixedMap<()>,
>(
  set: ValidatorSet,
) {
  let mut prefix = Storage::final_prefix().to_vec();
  prefix.extend(&set.encode());
  assert!(matches!(
    sp_io::storage::clear_prefix(&prefix, None),
    sp_io::KillStorageResult::AllRemoved(_)
  ));
}

pub(crate) enum AllocationError {
  NoAllocationPerKeyShareSet,
  AllocationLessThanKeyShare,
  IntroducesSinglePointOfFailure,
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

  /// Retire a validator set.
  ///
  /// This MUST be called only for sessions which are no longer current.
  fn retire(set: ValidatorSet);

  /// Increase a validator's allocation.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the book-keeping
  /// of it.
  fn increase_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
  ) -> Result<(), AllocationError>;
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
  }

  fn retire(set: ValidatorSet) {
    assert!(
      Some(set.session).map(|session| session.0) <
        Storage::CurrentSession::get(set.network).map(|session| session.0),
      "retiring a set which is active/upcoming"
    );
    // Clean-up this set's storage
    clear_selected_validators::<Storage::SelectedValidators>(set);
  }

  fn increase_allocation(
    network: NetworkId,
    validator: Public,
    amount: Amount,
  ) -> Result<(), AllocationError> {
    let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) else {
      Err(AllocationError::NoAllocationPerKeyShareSet)?
    };

    let old_allocation = Self::get_allocation(network, validator).unwrap_or(Amount(0));
    // Safe so long as the SRI supply fits within a u64, per assumptions on how this is called
    let new_allocation = (old_allocation + amount).unwrap();
    if new_allocation < allocation_per_key_share {
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
}
