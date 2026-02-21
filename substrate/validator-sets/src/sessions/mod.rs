//! This file implements the session attempt logic for Serai's networks and state management for
//! validator sets. Specifically, upon being instructed to attempt a new session, this will perform
//! the literal decision and save it. It will also prune information regarding historic sets,
//! defined as any set prior to the set prior to the prior session's. This corresponds to the
//! definition used when determining if deallocations should be delayed, and also ensures that any
//! set which is the current session will have its information available for the expected session
//! duration.
//!
//! Note the "prior to the set prior to the prior session's" is required to guarantee the current
//! session's information is so available. If the next set delays accepting the handover until
//! right before its next session will be decided, and then its next session immediately accepts
//! the handover (becoming current), what was the current session can become the prior prior
//! session within just a few blocks.

use alloc::vec::Vec;

use sp_core::{ConstU32, bounded::BoundedVec, sr25519::Public as SchnorrkelPublic};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    network_id::NetworkId,
    crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeys,
    balance::Amount,
    validator_sets::{
      KeyShares as KeySharesStruct, Session, ExternalValidatorSet, ValidatorSet,
      DeallocationTimeline,
    },
  },
  economic_security::EconomicSecurity as _,
  validator_sets::Event,
};

use frame_support::storage::{
  StorageValue, StorageMap, StorageDoubleMap as _, IterableStorageDoubleMap,
};

use serai_core_pallet::Pallet as Core;

use crate::{
  Emissions as _,
  allocations::{AllocationError, DeallocationError, Allocations, DelayedDeallocations},
  keys::Keys,
  pallet::AuxiliaryKeys as AuxiliaryKeysMap,
};

mod slash_reports;
pub(crate) use slash_reports::*;

/// The list of genesis validators.
pub(crate) type GenesisValidators =
  BoundedVec<SeraiAddress, ConstU32<{ KeySharesStruct::MAX_PER_SET_U32 }>>;

pub(crate) trait SessionsStorage:
  Allocations + DelayedDeallocations + Keys + SlashReports
{
  /// The configuration for the core pallet.
  type Config: crate::Config;

  /// The genesis validators
  ///
  /// The usage of is shared with the rest of the pallet. `Sessions` only reads it.
  type GenesisValidators: StorageValue<GenesisValidators, Query = Option<GenesisValidators>>;

  /// The allocation required for a key share.
  ///
  /// The usage of is shared with the rest of the pallet. `Sessions` only reads it.
  type AllocationPerKeyShare: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// The latest session which has been decided.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  type LatestDecidedSession: StorageMap<NetworkId, Session, Query = Option<Session>>;

  /// The current session.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  type CurrentSession: StorageMap<NetworkId, Session, Query = Option<Session>>;

  /// The amount of key shares a validator set has.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  /// This will be pruned for historical sessions however, as defined within the `Sessions`
  /// abstraction.
  type KeyShares: StorageMap<ValidatorSet, KeySharesStruct, Query = Option<KeySharesStruct>>;

  /// The selected validators for a set.
  ///
  /// The value will be the `Serai` auxiliary key for the validator and the amount of key shares
  /// the validator has within this set. This will be determined when the set is decided and static
  /// for the lifetime of the validator set. Validators' declared auxiliary keys may still be
  /// updated arbitrarily, but these updates will only be considered when deciding new sets.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  /// This will be pruned for historical sessions however, as defined within the `Sessions`
  /// abstraction.
  #[rustfmt::skip]
  type SelectedValidators:
    IterableStorageDoubleMap<
      ValidatorSet, SeraiAddress,
      (SchnorrkelPublic, KeySharesStruct), Query = Option<(SchnorrkelPublic, KeySharesStruct)>,
    >;

  /// The amount of allocated stake for a network's current session.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type CurrentAllocatedStake: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// The amount of allocated stake for a network's latest decided session.
  ///
  /// This is opaque and to be exclusively read/write by `Sessions`.
  type LatestDecidedAllocatedStake: StorageMap<NetworkId, Amount, Query = Option<Amount>>;
}

pub(crate) trait Sessions {
  /// Attempt to spawn a new session for the specified network.
  ///
  /// Validators will be selected by their allocations if `AllocationPerKeyShare` is set for this
  /// network. `include_genesis_validators` will cause genesis validators to be included *with
  /// priority over all other validators*.
  ///
  /// This will not decide a new session if the latest decided session has yet to accept the
  /// handover and become current. This bounds the current session to be either the latest decided
  /// session or the one prior.
  ///
  /// This will emit the expected event defined within [`serai-abi`].
  ///
  /// This will return `true` if the next session was decided or `false` otherwise.
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool) -> bool;

  /// Have the latest-decided session accept the handover from the current set.
  ///
  /// Every decided set must accept the handover to become current.
  ///
  /// This has undefined behavior, potentially panicking, if the latest-decided session has already
  /// accepted the handover or if there was no latest-decided session. This MUST only be called
  /// once per decided session.
  ///
  /// This will emit the expected event defined within [`serai-abi`].
  fn accept_handover(network: NetworkId);

  /// Increase a validator's allocation.
  ///
  /// Like `Allocations::increase_allocation_without_updating_other_contexts`, this will never
  /// error when a reward for a validator who has set auxiliary keys.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for the allocation.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(())`.
  fn increase_allocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
    reward: bool,
  ) -> Result<(), AllocationError>;

  /// Decrease a validator's allocation.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for the deallocation.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(_)`.
  fn decrease_allocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> Result<DeallocationTimeline, DeallocationError>;

  /// The stake for the current validator set.
  ///
  /// This will return `None` if and only if there is no current validator set.
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount>;

  /// The stake for the latest decided validator set.
  ///
  /// This will return `None` if and only if there is no latest decided validator set.
  fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount>;
}

impl<Storage: SessionsStorage> Sessions for Storage {
  fn attempt_new_session(network: NetworkId, include_genesis_validators: bool) -> bool {
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

    // Select validators by who has the most stake allocated
    let mut selected_validators = Vec::with_capacity(usize::from(KeySharesStruct::MAX_PER_SET / 2));
    let mut total_key_shares = 0;
    if let Some(allocation_per_key_share) = Storage::AllocationPerKeyShare::get(network) {
      for (validator, amount) in Self::iter_allocations(network, allocation_per_key_share) {
        let key_shares = KeySharesStruct::from_allocation(amount, allocation_per_key_share);
        selected_validators.push((validator, key_shares));
        total_key_shares += u16::from(key_shares);
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
        .expect("genesis validators weren't set")
        .into_iter()
        .map(|validator| {
          // This won't panic due to the bound for the `BoundedVec` representing genesis validators
          total_key_shares += 1;
          (validator, KeySharesStruct::ONE)
        })
        .collect::<Vec<_>>();

      /*
        We shouldn't be including genesis validators if we have a healthy decentralized set of
        validators available. We also can't apply the reverse round robin here as the genesis
        validators only have a single key share and could be eliminated by reverse round robin,
        when they're expected to have the highest priority.

        Because this shouldn't occur, and because the proper method of reduction is inapplicable,
        we employ the native strategy of simply outright removing the least-allocating validators
        to make room for the genesis validators. This only produces a suboptimal result for severe
        edge cases when again, this isn't expected to occur in the first place.
      */
      while total_key_shares > KeySharesStruct::MAX_PER_SET {
        let (_key, key_shares) = selected_validators.pop().unwrap();
        total_key_shares -= u16::from(key_shares);
      }

      selected_validators.append(&mut genesis_validators);
    }

    // If we failed to select any validators, return `false` now
    if total_key_shares == 0 {
      return false;
    }

    let mut latest_decided_allocated_stake = Amount(0);
    for (validator, _key_shares) in &selected_validators {
      // Safe as the entire supply will fit within an `Amount` per `serai-coins-pallet`'s bounds
      latest_decided_allocated_stake = (latest_decided_allocated_stake +
        Self::allocation(network, *validator).unwrap_or(Amount(0)))
      .unwrap();
    }
    // Only rotate to this set if they have sufficient stake
    match network {
      NetworkId::Serai => {}
      NetworkId::External(network) => {
        let achieved_economic_security =
          <Storage::Config as crate::Config>::EconomicSecurity::achieved_economic_security(network);
        if achieved_economic_security &&
          (latest_decided_allocated_stake <
            crate::network_stake_requirement::<
              Storage::Config,
              <Storage::Config as crate::Config>::EconomicSecurity,
            >(network))
        {
          return false;
        }
      }
    }

    let latest_decided_session = Storage::LatestDecidedSession::mutate(network, |session| {
      let next_session = session.map(|session| Session(session.0 + 1)).unwrap_or(Session(0));
      *session = Some(next_session);
      next_session
    });

    Storage::LatestDecidedAllocatedStake::set(network, Some(latest_decided_allocated_stake));

    let latest_decided_set = ValidatorSet { network, session: latest_decided_session };
    Storage::KeyShares::insert(
      latest_decided_set,
      KeySharesStruct::try_from(total_key_shares).expect("amortization failure"),
    );
    for (validator, key_shares) in &selected_validators {
      /*
        It's a documented invariant that all validators, for any network, must have this auxiliary
        key set. Currently, it's enforced by all genesis validators being required to set auxiliary
        keys for _every_ network, and auxiliary keys being required to be set _before_ stake may
        be allocated.

        As those are the only two ways to qualify to be selected as a validator, this invariant
        holds.
      */
      let AuxiliaryKeys::Serai(aux_key) =
        AuxiliaryKeysMap::<Storage::Config>::get(NetworkId::Serai, validator)
          .expect("selected validator didn't have a `Serai` auxiliary key set")
      else {
        panic!("auxiliary key for `Serai` wasn't `Serai`")
      };
      Storage::SelectedValidators::insert(
        latest_decided_set,
        validator,
        (SchnorrkelPublic::from(aux_key), key_shares),
      );
    }

    Core::<Storage::Config>::emit_event(Event::SetDecided {
      set: latest_decided_set,
      validators: selected_validators.into_iter().collect(),
    });

    true
  }

  fn accept_handover(network: NetworkId) {
    let (prior, current) = {
      let current = Storage::CurrentSession::get(network);
      // This is allowed to panic here (per its documented bounds) and should for safety reasons
      let latest_decided = Storage::LatestDecidedSession::get(network)
        .expect("accepting handover but never decided a session");
      assert_eq!(
        current,
        latest_decided.0.checked_sub(1).map(Session),
        "current session wasn't prior to latest-decided"
      );

      Storage::CurrentSession::set(network, Some(latest_decided));
      // Return `current` as the `prior` session and `latest_decided` as the `current` session
      (current, latest_decided)
    };

    // Update `CurrentAllocatedStake`
    Storage::CurrentAllocatedStake::set(
      network,
      Some(
        Storage::LatestDecidedAllocatedStake::get(network)
          .expect("accepting handover but never set latest decided set's stake"),
      ),
    );

    // If there was a prior set, retire it within the `SlashReports` abstractions
    if let Some(prior) = prior {
      match network {
        NetworkId::Serai => {}
        NetworkId::External(network) => {
          let retiring = ExternalValidatorSet { network, session: prior };
          <Self as SlashReports>::retire_set_regarding_slash_report(
            retiring,
            <Storage::Config as crate::Config>::Emissions::take_set_reward(retiring),
          );
        }
      }
    }

    // Clean-up the historic set's storage, if one exists
    if let Some(historic_session) = current.0.checked_sub(3).map(Session) {
      let historic_set = ValidatorSet { network, session: historic_session };

      // Remove the storage within this abstraction
      Storage::KeyShares::remove(historic_set);
      for _ in Storage::SelectedValidators::drain_prefix(historic_set) {}

      // Remove the storage for this set within other abstractions
      match historic_set.network {
        NetworkId::Serai => {}
        NetworkId::External(network) => {
          let historic_set = ExternalValidatorSet { network, session: historic_session };
          <Self as Keys>::prune_historical_set_regarding_keys(historic_set);
          <Self as SlashReports>::prune_historical_set_regarding_slash_report(historic_set);
        }
      }
    }

    Core::<Storage::Config>::emit_event(Event::AcceptedHandover {
      set: ValidatorSet { network, session: current },
    });
  }

  fn increase_allocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
    reward: bool,
  ) -> Result<(), AllocationError> {
    /*
      Per the documented bounds on `trait Allocations`, this function will be atomic. As this
      function will not error after this call, only update its own storage, this function inherits
      the desirable atomicity.
    */
    <Self as Allocations>::increase_allocation_without_updating_other_contexts(
      network, validator, amount, reward,
    )?;

    // If this validator is active, update `CurrentAllocatedStake`
    if let Some(current) = Storage::CurrentSession::get(network) {
      if Storage::SelectedValidators::contains_key(
        ValidatorSet { network, session: current },
        validator,
      ) {
        Storage::CurrentAllocatedStake::mutate(network, |existing| {
          /*
            The `expect` regarding `CurrentAllocatedStake` is guaranteed by the behavior within
            this file, as `CurrentAllocatedStake` is owned by this abstraction.

            The `unwrap` on this addition is safe so long as the supply fits within an `Amount`, as
            `serai-coins-pallet` guarantees.
          */
          Some((existing.expect("current session but no allocated stake set") + amount).unwrap())
        });
      }
    }

    // The same, but for the latest decided session
    if let Some(latest_decided) = Storage::LatestDecidedSession::get(network) {
      if Storage::SelectedValidators::contains_key(
        ValidatorSet { network, session: latest_decided },
        validator,
      ) {
        Storage::LatestDecidedAllocatedStake::mutate(network, |existing| {
          Some(
            (existing.expect("latest decided session but no allocated stake set") + amount)
              .unwrap(),
          )
        });
      }
    }

    Ok(())
  }

  fn decrease_allocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> Result<DeallocationTimeline, DeallocationError> {
    let in_latest_decided_session =
      if let Some(latest_decided_session) = Storage::LatestDecidedSession::get(network) {
        if Storage::SelectedValidators::contains_key(
          ValidatorSet { network, session: latest_decided_session },
          validator,
        ) {
          match network {
            NetworkId::Serai => {}
            NetworkId::External(network) => {
              // Check this doesn't cause the latest decided session to become insecure
              if (Storage::LatestDecidedAllocatedStake::get(network)
                .expect("latest decided session but no allocated stake set") -
                amount)
                .expect("validator in set deallocated stake the set didn't have") <
                crate::network_stake_requirement::<
                  Storage::Config,
                  <Storage::Config as crate::Config>::EconomicSecurity,
                >(network)
              {
                Err(DeallocationError::EconomicSecurity)?;
              }
            }
          }
          true
        } else {
          false
        }
      } else {
        false
      };

    /*
      Decrease the allocation.

      This doesn't affect the key shares, as that's immutable after creation, and doesn't affect
      affect the `CurrentAllocatedStake` as the validator either isn't current or the deallocation
      will be queued *but is still considered allocated for this session*.

      When the next set is selected, and becomes current, `CurrentAllocatedStake` will be updated
      per the allocations as-is.

      This is the last call which may error, the called function is atomic, and all effects happen
      after this call, making this function atomic.
    */
    <Self as Allocations>::decrease_allocation_without_updating_other_contexts(
      network, validator, amount,
    )?;

    // This does affect `LatestDecidedAllocatedStake`, as expected
    if in_latest_decided_session {
      Storage::LatestDecidedAllocatedStake::mutate(network, |existing| {
        Some(
          (existing.expect("latest decided session but no allocated stake set") - amount)
            .expect("validator in set deallocated stake the set didn't have"),
        )
      });
    }

    Ok(Self::potentially_delay_deallocation(network, validator, amount))
  }

  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Storage::CurrentAllocatedStake::get(network)
  }

  fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
    Storage::LatestDecidedAllocatedStake::get(network)
  }
}
