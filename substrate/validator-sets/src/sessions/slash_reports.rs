use alloc::vec::Vec;

use sp_core::sr25519::Public as SchnorrkelPublic;

use serai_abi::{
  primitives::{
    address::SeraiAddress, network_id::NetworkId, coin::Coin, balance::*, validator_sets::*,
  },
  validator_sets::Event,
};

use frame_support::{traits::OneSessionHandler as _, storage::StorageMap};

use serai_core_pallet::Pallet as Core;

use crate::{
  keys::KeysStorage,
  allocations::{Allocations, DelayedDeallocations},
  sessions::Sessions,
};

pub(crate) trait SlashReportsStorage:
  KeysStorage + Allocations + DelayedDeallocations + Sessions
{
  /// The configuration for the core pallet.
  type Config: crate::Config;

  /// Validator sets for which we're awaiting slash reports.
  ///
  /// This is opaque and to be exclusively read/write by `SlashReports`.
  ///
  /// Internally, the value is the amount to reward the validator set with.
  type PendingSlashReport: StorageMap<ExternalValidatorSet, Amount, Query = Option<Amount>>;
}

pub(crate) trait SlashReports {
  /// Mark a validator set as retired.
  ///
  /// This will cause the validator set to be marked to publish a slash report, if expected to.
  fn retire_set_regarding_slash_report(set: ExternalValidatorSet, rewards: Amount);

  /// Prune a historical validator set.
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
  fn slash_serai_validator(session: Session, validator: SeraiAddress);
}

fn fatal_slash<Storage: SlashReportsStorage>(network: NetworkId, validator: SeraiAddress) {
  let mut drained = if let Some(amount) = Storage::drain_allocation(network, validator) {
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

  drained.0 += Storage::drain_delayed_deallocations(network, validator).0;

  /*
    This should only error if we do not have these coins, which would suggest an accounting
    invariant where we allocated stake we didn't hold.

    `clippy::disallowed_methods` as this method can, but shouldn't, be called for
    non-`CoinsInstance`. `crate::Coins` points to `CoinsInstance`, making this safe.
  */
  #[expect(clippy::disallowed_methods)]
  crate::Coins::<Storage::Config>::burn(
    Some(crate::Pallet::<Storage::Config>::account()).into(),
    Balance { coin: Coin::Serai, amount: drained },
  )
  .expect("couldn't burn coins we slashed");
}

fn handle_slash_report<Storage: SlashReportsStorage>(
  set: ExternalValidatorSet,
  slashes: Option<SlashReport>,
) {
  let rewards =
    Storage::PendingSlashReport::take(set).expect("handling a slash report which wasn't pending");
  Core::<Storage::Config>::emit_event(Event::Slashes { set: set.into() });

  // If no report was submitted, do not distribute any rewards
  let Some(slashes) = slashes else { return };

  let validators =
    crate::SelectedValidators::<Storage::Config>::iter_key_prefix(set).collect::<Vec<_>>();
  assert_eq!(validators.len(), slashes.0.len());
  let validators_len = u16::try_from(validators.len())
    .expect("selected more than `u16::MAX` (`KeyShares` repr) validators?");
  let reward_per_validator = Amount(rewards.0 / u64::from(validators_len));
  let validators_len =
    core::num::NonZero::new(validators_len).expect("selected validator set without validators?");

  // Distribute rewards as expected
  for (validator, slash) in validators.into_iter().zip(slashes.0) {
    /*
      We specify `Amount(0)` as the amount this validator has allocated. Introspecting
      `Slash::penalty`, it's only used on `Slash::Fatal` which we handle ourselves. This aligns
      with the intent where allocated stake is only slashed on misbehavior (fatal), not downtime
      (points). This is because it's surprisingly annoying to calculate the amount a validator
      allocated as stake during this specific set. It would require tracking another balance
      sheet for every single session.
    */
    match &slash {
      Slash::Points(_) => {
        let penalty = slash.penalty(validators_len, Amount(0), reward_per_validator);
        let reward = (reward_per_validator - penalty).unwrap_or(Amount(0));
        if crate::Coins::<Storage::Config>::mint(
          crate::Pallet::<Storage::Config>::account(),
          Balance { coin: Coin::Serai, amount: reward },
        )
        .is_ok()
        {
          // This is a safe `unwrap` per the documented bounds on `increase_allocation`
          Storage::increase_allocation(set.network.into(), validator, reward, true).unwrap();
        }
      }
      Slash::Fatal => fatal_slash::<Storage>(set.network.into(), validator),
    }
  }
}

impl<Storage: SlashReportsStorage> SlashReports for Storage {
  fn retire_set_regarding_slash_report(set: ExternalValidatorSet, rewards: Amount) {
    Storage::PendingSlashReport::insert(set, rewards);
  }

  fn prune_historical_set_regarding_slash_report(set: ExternalValidatorSet) {
    // If this network never submitted its slash report, treat it as submitting `vec![]`
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

  fn slash_serai_validator(session: Session, validator: SeraiAddress) {
    let network = NetworkId::Serai;
    let set = ValidatorSet { network, session };
    Core::<Storage::Config>::emit_event(Event::Slashes { set });
    fatal_slash::<Self>(network, validator);

    // If this for the current session, disable them
    if session ==
      crate::pallet::CurrentSession::<Storage::Config>::get(network)
        .expect("slashing Serai validator yet no current session for Serai?")
    {
      // Panicking here is fine as a majority of Serai validators approved an invalid inherent
      let i = crate::Pallet::<Storage::Config>::selected_validators(set)
        .position(|(this_validator, _)| this_validator == validator)
        .expect("slashing Serai validator who was not in the alleged session");
      let i = u32::try_from(i).unwrap();
      crate::Babe::<Storage::Config>::on_disabled(i);
      crate::Grandpa::<Storage::Config>::on_disabled(i);
    }
  }
}
