use alloc::vec::Vec;

use sp_core::{ConstU32, bounded::BoundedVec, sr25519::Public as SchnorrkelPublic};

use serai_abi::{
  primitives::{
    address::SeraiAddress, network_id::NetworkId, coin::Coin, balance::*, validator_sets::*,
  },
  validator_sets::{ReportedSlashes, Event},
};

use frame_support::{traits::OneSessionHandler as _, storage::StorageMap};

use serai_core_pallet::Pallet as Core;

use crate::{
  keys::KeysStorage,
  allocations::{Allocations, DelayedDeallocations},
  sessions::{SessionsStorage, Sessions as _},
};

/// The value storing the data for a pending slash report.
pub(crate) type PendingSlashReport =
  BoundedVec<(SeraiAddress, Amount), ConstU32<{ KeyShares::MAX_PER_SET_U32 }>>;

pub(crate) trait SlashReportsStorage:
  KeysStorage + Allocations + DelayedDeallocations + SessionsStorage
{
  /// Validator sets for which we're awaiting slash reports.
  ///
  /// This is opaque and to be exclusively read/write by `SlashReports`.
  ///
  /// Internally, the value is the list of validators with the amount to reward each with _prior_
  /// to the calculation of any slashes.
  type PendingSlashReport: StorageMap<
    ExternalValidatorSet,
    PendingSlashReport,
    Query = Option<PendingSlashReport>,
  >;
}

pub(crate) trait SlashReports {
  /// Mark a validator set as retired.
  ///
  /// This will cause the validator set to be marked to publish a slash report, if expected to.
  fn retire_set_regarding_slash_report(set: ExternalValidatorSet, rewards: Amount);

  /// Prune a historical validator set.
  ///
  /// This MUST be called when a validator set becomes historical.
  ///
  /// If this validator set was expected to and has yet to publish a slash report, a default
  /// (empty) slash report will be entered.
  fn prune_historical_set_regarding_slash_report(set: ExternalValidatorSet);

  /// Handle a slash report.
  ///
  /// This has undefined behavior, potentially panicking, if the set is not currently expected to
  /// publish a slash report. This MUST only be called for sets which are currently expected to.
  /// The same is true if the slash report has a length distinct from the amount of validators
  /// present within the specified set.
  fn handle_slash_report(set: ExternalValidatorSet, slashes: SlashReport);

  /// If this set is still expected to publish a slash report.
  ///
  /// If so, this returns the oraclization key which should sign the slash report.
  fn should_still_publish_slash_report(set: ExternalValidatorSet) -> Option<SchnorrkelPublic>;

  /// Slash a Serai validator for their entire stake.
  ///
  /// This will emit a `Deallocation` event for the amount slashed which was actively allocated,
  /// ensuring the event log actively represents the current allocations. This will also emit the
  /// `Slashes` event.
  ///
  /// The slashed coins will be burnt.
  fn slash_serai_validator(validator: SeraiAddress);
}

fn fatal_slash<Storage: SlashReportsStorage>(network: NetworkId, validator: SeraiAddress) {
  let mut drained = if let Some(amount) = Storage::drain_allocation(validator, network) {
    // Emit the `Deallocation` event for the amount we drained
    Core::<Storage::Config>::emit_event(Event::Deallocation {
      validator,
      network,
      amount,
      timeline: DeallocationTimeline::Immediate,
    });
    amount
  } else {
    Amount(0)
  };

  drained.0 += Storage::drain_delayed_deallocations(validator, network).0;

  /*
    This should only error if we do not have these coins, which would suggest an accounting
    invariant where we allocated stake we didn't hold.

    `clippy::disallowed_methods` as this method can, but shouldn't, be called for
    non-`CoinsInstance`. `crate::Coins` points to `CoinsInstance`, making this safe.
  */
  #[expect(clippy::disallowed_methods)]
  crate::Coins::<Storage::Config>::burn(
    Some(serai_abi::validator_sets::address()).into(),
    Balance { coin: Coin::Serai, amount: drained },
  )
  .expect("couldn't burn coins we slashed");
}

fn handle_slash_report<Storage: SlashReportsStorage>(
  set: ExternalValidatorSet,
  slashes: Option<SlashReport>,
) {
  let validators_with_rewards =
    Storage::PendingSlashReport::take(set).expect("handling a slash report which wasn't pending");

  // If no report was submitted, do not distribute any rewards
  let Some(slashes) = slashes else { return };
  assert_eq!(validators_with_rewards.len(), slashes.0.len());

  let validators_len = u16::try_from(validators_with_rewards.len())
    .expect("selected more than `u16::MAX` (`KeyShares` repr) validators?");
  let validators_len =
    core::num::NonZero::new(validators_len).expect("selected validator set without validators?");

  // Distribute rewards as expected
  for ((validator, reward_for_validator), slash) in
    validators_with_rewards.into_iter().zip(slashes.0)
  {
    /*
      We specify `Amount(0)` as the amount this validator has allocated. Introspecting
      `Slash::penalty`, it's only used on `Slash::Fatal` which we handle ourselves. This aligns
      with the intent where allocated stake is only slashed on misbehavior (fatal), not downtime
      (points). This avoids us having to propagation `allocation` from when this slash report was
      queued and discussing whether we should propagate `allocation` or `virtual_stake`.
    */
    match &slash {
      Slash::Points(_) => {
        let penalty = slash.penalty(validators_len, Amount(0), reward_for_validator);
        let reward_for_validator = (reward_for_validator - penalty).unwrap_or(Amount(0));
        if crate::Coins::<Storage::Config>::mint(
          serai_abi::validator_sets::address(),
          Balance { coin: Coin::Serai, amount: reward_for_validator },
        )
        .is_ok()
        {
          // This is a safe `unwrap` per the documented bounds on `increase_allocation`
          Storage::increase_allocation(set.network.into(), validator, reward_for_validator, true)
            .unwrap();
        }
      }
      Slash::Fatal => fatal_slash::<Storage>(set.network.into(), validator),
    }
  }

  Core::<Storage::Config>::emit_event(Event::Slashes(ReportedSlashes::ExternalValidatorSet(set)));
}

impl<Storage: SlashReportsStorage> SlashReports for Storage {
  fn retire_set_regarding_slash_report(set: ExternalValidatorSet, rewards: Amount) {
    // Note fetching this now assumes it hasn't changed since the set was decided
    let allocation_per_key_share = Storage::AllocationPerKeyShare::get(set.network);
    let validators_with_virtual_stakes =
      crate::SelectedValidators::<Storage::Config>::iter_prefix(set)
        .map(|(validator, (_aux_key, key_shares))| {
          /*
            We reward validators proportionally to what they do for the network. In order to
            incentivize validators to allocate according to key shares, as required for the literal
            cryptographic distribution of key shares to correspond with the distribution of
            allocated stake, stake which does not effect a key share is only considered for half
            its value.
          */
          let virtual_stake = if let Some(allocation_per_key_share) = allocation_per_key_share {
            let allocation = {
              // Fetch their current allocation as would've applied to the current set now retiring
              let allocation =
                Storage::allocation(set.network.into(), validator).unwrap_or(Amount(0));
              // Also fetch their delayed deallocation as it would have still contributed to this
              // set
              let delayed_deallocation = Storage::fetch_deallocations_delayed_from(
                validator,
                set.network.into(),
                set.session,
              )
              .unwrap_or(Amount(0));
              // The SRI supply fits within a `u64` so this part of it will
              (allocation + delayed_deallocation).unwrap()
            };

            /*
              Note:
              - This will reward genesis validators for as if they had stake behind their key
                shares.
              - The amount will be `<= allocation` except in the edge case
                `stake_corresponding_to_key_shares` exceeds `allocation`, as is the case when
                genesis validators are present. That's why this yields a `u128`.
            */
            let stake_corresponding_to_key_shares =
              u128::from(u16::from(key_shares)) * u128::from(allocation_per_key_share.0);
            stake_corresponding_to_key_shares +
              ((u128::from(allocation.0).saturating_sub(stake_corresponding_to_key_shares)) / 2)
          } else {
            1
          };
          (validator, virtual_stake)
        })
        .collect::<Vec<_>>();

    // This won't overflow so long as `KeyShares` is representable within a `u64`
    let total_virtual_stake_for_validators = validators_with_virtual_stakes
      .iter()
      .map(|(_validator, virtual_stake)| virtual_stake)
      .sum::<u128>();

    // Map from the virtual stake to their reward
    let validators_with_rewards = validators_with_virtual_stakes
      .into_iter()
      .map(|(validator, virtual_stake)| {
        (
          validator,
          Amount(
            u64::try_from(
              (sp_core::U256::from(u128::from(rewards.0)) * sp_core::U256::from(virtual_stake)) /
                sp_core::U256::from(total_virtual_stake_for_validators),
            )
            .expect("`virtual_stake > total_virtual_stake_for_validators`?"),
          ),
        )
      })
      .collect::<Vec<_>>();

    Storage::PendingSlashReport::insert(
      set,
      PendingSlashReport::try_from(validators_with_rewards)
        .expect("more validators in set than allowed by `KeyShares::MAX_PER_SET`?"),
    );
  }

  fn prune_historical_set_regarding_slash_report(set: ExternalValidatorSet) {
    if Storage::PendingSlashReport::contains_key(set) {
      handle_slash_report::<Storage>(set, None);
    }
  }

  fn handle_slash_report(set: ExternalValidatorSet, slashes: SlashReport) {
    handle_slash_report::<Storage>(set, Some(slashes));
  }

  fn should_still_publish_slash_report(set: ExternalValidatorSet) -> Option<SchnorrkelPublic> {
    Storage::PendingSlashReport::contains_key(set).then(|| {
      Storage::OraclizationKeys::get(set)
        .expect("no oraclization key for set which should still publish a slash report")
    })
  }

  fn slash_serai_validator(validator: SeraiAddress) {
    let network = NetworkId::Serai;
    fatal_slash::<Self>(network, validator);
    Core::<Storage::Config>::emit_event(Event::Slashes(ReportedSlashes::SeraiValidator(validator)));

    /*
      If the validator is current and now disabled, emit the relevant BABE/GRANDPA logs.

      This is premised on how an already-disabled validator's slash would be considered stale and
      not pass validation. If this assumption is wrong, then a validator may have the disabled
      event emitted multiple times, though this isn't considered an issue.

      This does not consider how a validator may be _re-enabled_ if the validator proceeds to
      re-allocate sufficient stake, as BABE/GRANDPA do not have such logs. As this log is seemingly
      only intended for light clients, being entirely without consumption in the actual Serai node,
      the real comment is light clients should not peruse these logs but rather Serai's own events
      to determine the current validators.

      TODO: Make this understanding concrete by patching `polkadot-sdk` to remove this flow
      entirely, ensuring it was as described and isn't extended to new usage in the future.
    */
    let current_session = crate::Pallet::<Storage::Config>::current_session(NetworkId::Serai)
      .expect("Serai validator is being slashed before Serai had a session begin");
    if let Some(disabled_validator_i) =
      crate::Pallet::<Storage::Config>::selected_validators(ValidatorSet {
        network: NetworkId::Serai,
        session: current_session,
      })
      .enumerate()
      .find_map(|(i, (this_validator, _auxiliary_keys))| {
        (this_validator == validator)
          .then_some(u32::try_from(i).expect("amount of validators in set exceeded `u32`"))
      })
      .filter(|i| {
        <crate::Pallet<Storage::Config> as frame_support::traits::DisabledValidators>::is_disabled(
          *i,
        )
      })
    {
      crate::Babe::<Storage::Config>::on_disabled(disabled_validator_i);
      crate::Grandpa::<Storage::Config>::on_disabled(disabled_validator_i);
    }
  }
}
