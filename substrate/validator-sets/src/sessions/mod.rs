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

  /// The amount of stake considered allocated for a network's current session.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  /// This will be `None` if and only if there is no current validator set for this network.
  type CurrentAllocatedStake: StorageMap<NetworkId, Amount, Query = Option<Amount>>;

  /// The amount of stake considered allocated for a network's latest decided session.
  ///
  /// This is to be solely written to by `Sessions`, but may be read by the rest of the pallet.
  /// This will be `None` if and only if there is no latest decided validator set for this network.
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
  /// This will emit the expected event defined within [`serai-abi`].
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
  /// This will emit the expected event defined within [`serai-abi`].
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(_)`.
  fn decrease_allocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> Result<DeallocationTimeline, DeallocationError>;
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
        .filter(|genesis_validator| {
          !selected_validators.iter().any(|(already_selected_validator, _key_shares)| {
            already_selected_validator == genesis_validator
          })
        })
        .map(|genesis_validator| {
          // This won't panic due to the collection storing genesis validators being bounded
          total_key_shares += 1;
          (genesis_validator, KeySharesStruct::ONE)
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

    // Fetch the network stake requirement
    let network_stake_requirement = match network {
      NetworkId::Serai => Amount(0),
      NetworkId::External(network) => {
        if <Storage::Config as crate::Config>::EconomicSecurity::achieved_economic_security(network)
        {
          crate::network_stake_requirement::<
            Storage::Config,
            <Storage::Config as crate::Config>::EconomicSecurity,
          >(network)
        } else {
          Amount(0)
        }
      }
    };

    let stake_for_validators = |selected_validators: &[_]| {
      let mut stake = Amount(0);
      for (validator, _key_shares) in selected_validators {
        // Safe as the entire supply will fit within an `Amount` per `serai-coins-pallet`'s bounds
        stake = (stake + Self::allocation(network, *validator).unwrap_or(Amount(0))).unwrap();
      }
      stake
    };

    /*
      If the stake for these validators is less than the requirement, insert genesis validators,
      even if we weren't instructed to, if they have any amount allocated.

      The exact issue this aims to solve is how immediately post-Economic Security, genesis
      validators will have been minted rewards _but may be less than the allocation per key share_.
      This means they _may_ be providing capacity but _may not_ be selected for the next session,
      causing the set to immediately stall after achieving Economic Security.

      This block _solely_ excepts genesis validators from the `AllocationPerKeyShare` minimum when
      and only when the proposed set would not otherwise achieve economic security.
    */
    if stake_for_validators(&selected_validators) < network_stake_requirement {
      let mut genesis_validators = Storage::GenesisValidators::get()
        .expect("genesis validators weren't set")
        .into_iter()
        .filter(|genesis_validator| {
          !selected_validators.iter().any(|(already_selected_validator, _key_shares)| {
            already_selected_validator == genesis_validator
          })
        })
        .map(|genesis_validator| {
          let allocation = Self::allocation(network, genesis_validator).unwrap_or(Amount(0));
          (allocation, genesis_validator)
        })
        .collect::<Vec<_>>();
      // Sort the genesis validators by how much they actively have allocated as stake
      genesis_validators.sort_by(
        |(a_allocation, _a_genesis_validator), (b_allocation, _b_genesis_validator)| {
          a_allocation.cmp(b_allocation).reverse()
        },
      );
      for (allocation, genesis_validator) in genesis_validators {
        // Push genesis validators while they fit and contribute to economic security
        if (total_key_shares >= KeySharesStruct::MAX_PER_SET) || (allocation == Amount(0)) {
          break;
        }
        total_key_shares += 1;
        selected_validators.push((genesis_validator, KeySharesStruct::ONE));
      }
    }

    // If we failed to select any validators, return `false` now
    if total_key_shares == 0 {
      return false;
    }

    let latest_decided_allocated_stake = stake_for_validators(&selected_validators);
    // Only rotate to this set if they have sufficient stake
    if latest_decided_allocated_stake < network_stake_requirement {
      return false;
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
      function will not error after this call, only updating the storage, this function inherits
      the desirable atomicity.
    */
    <Self as Allocations>::increase_allocation_without_updating_other_contexts(
      network, validator, amount, reward,
    )?;

    crate::Core::<Storage::Config>::emit_event(Event::Allocation { validator, network, amount });

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
    /*
      Decrease the allocation.

      This doesn't affect the key shares, as that's immutable after creation, and doesn't affect
      affect the `CurrentAllocatedStake` as the validator either isn't current or the deallocation
      will be queued *but is still considered allocated for this session*. The same holds true for
      `LatestDecidedAllocatedStake` where the validator either won't be in the latest decided set
      or the deallocation will be queued *but is still considered allocated for that session*.

      When the latest decided set becomes current, `CurrentAllocatedStake` will be updated to
      `LatestDecidedAllocatedStake`. When a new set is decided, `LatestDecidedAllocatedStake` will
      be updated to the allocations as they are.

      This is the last call which may error, the called function is atomic, and all effects happen
      after this call, making this function atomic.
    */
    <Self as Allocations>::decrease_allocation_without_updating_other_contexts(
      network, validator, amount,
    )?;

    let timeline = Self::potentially_delay_deallocation(network, validator, amount);
    Core::<Storage::Config>::emit_event(Event::Deallocation {
      validator,
      network,
      amount,
      timeline,
    });
    Ok(timeline)
  }
}
