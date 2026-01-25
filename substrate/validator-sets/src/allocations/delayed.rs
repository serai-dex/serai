use alloc::vec;

use scale::Encode as _;

use serai_abi::primitives::{
  address::SeraiAddress,
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{Session, ValidatorSet, DeallocationTimeline},
};

use frame_support::storage::{StorageMap as _, StorageDoubleMap as _, IterableStorageDoubleMap};

use crate::sessions::SessionsStorage;

pub(crate) trait DelayedDeallocationsStorage: SessionsStorage {
  /// The delayed deallocations.
  ///
  /// The second key's hasher MUST be `Identity`.
  ///
  /// This is opaque and to be exclusively read/write by `DelayedDeallocations`.
  ///
  /// Internally, the `ValidatorSet` is the set the deallocation was delayed _until_. It is not the
  /// set the deallocation was delayed _from_.
  #[rustfmt::skip]
  type DelayedDeallocations: IterableStorageDoubleMap<
    SeraiAddress,
    ValidatorSet,
    Amount,
    Query = Option<Amount>
  >;
}

/// An error when claiming a delayed deallocation.
#[derive(
  scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
)]
pub enum DelayedDeallocationError {
  /// The delay has yet to be satisfied.
  DelayNotSatisfied,
  /// No delayed deallocation was present.
  NoDelayedDeallocations,
}

pub(crate) trait DelayedDeallocations {
  /// Potentially delay a validator's deallocation.
  ///
  /// This function will determine if a deallocation should be delayed, as to not immediately
  /// deallocate stake from active validators who may still be subject to a slash. It will yield a
  /// [`DeallocationTimeline`], and if the deallocation should be delayed, register it within its
  /// storage to be claimed later. If [`DeallocationTimeline::Immediate`] is returned, the caller
  /// is expected to handle the deallocation immediately.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// for registering the deallocation with regards to the [`DelayedDeallocations`] abstraction
  /// present here, if a delay should apply.
  fn potentially_delay_deallocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> DeallocationTimeline;

  /// Remove all actively-delayed deallocations for the cited validator.
  ///
  /// This is intended to be called in response to a fatal slash. It will remove all entries for
  /// the actively-delayed allocations, preventing them from being claimed. It will return the
  /// sum amount so drained.
  fn drain_delayed_deallocations(network: NetworkId, validator: SeraiAddress) -> Amount;

  /// Claim a delayed deallocation.
  ///
  /// This will validate there was a deallocation delayed until `session` and return how much was
  /// deallocated and should be yielded now.
  ///
  /// This does not perform any transfers of any coins/tokens. It solely performs the bookkeeping
  /// of for consuming the pending deallocation.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(_)`.
  fn claim_delayed_deallocation(
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  ) -> Result<Amount, DelayedDeallocationError>;
}

impl<Storage: DelayedDeallocationsStorage> DelayedDeallocations for Storage {
  fn potentially_delay_deallocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> DeallocationTimeline {
    /*
      For a validator present in set #n, they should only be able to deallocate once set #n+3 is
      current. This ensures at least the intended duration of a session is provided to halt further
      handovers (along with associated pending deallocations).

      We find the most recent session this validator was in (which would still be subject to a
      delay) before determining the session this deallocation should unlock at.
    */
    let find_most_recent_session_for_validator = || {
      let check_presence = |session| {
        // This will be pruned for historical sessions, but the sessions we check aren't historical
        // per the definition in the `Sessions` abstraction (which aligns with here)
        Storage::SelectedValidators::contains_key(ValidatorSet { network, session }, validator)
      };

      if let Some(mut session) = Storage::LatestDecidedSession::get(network) {
        /*
          We check the latest decided session, current session, prior session, and prior prior
          session.

          If the prior prior session has index #0, then deallocations from validators active during
          it should only be able to claim their deallocation after session #2 has completed. As the
          current session is #2, delays from the prior prior session would still be in effect.
        */
        for _ in 0 .. 4 {
          if check_presence(session) {
            return Some(session);
          }
          let Some(prior_session) = session.0.checked_sub(1) else { break };
          session = Session(prior_session);
        }
      }
      None
    };
    if let Some(present_in_session) = find_most_recent_session_for_validator() {
      /*
        Because they were present in the found session, determine the session this deallocation
        will unlock at.

        The session with an index of `+ 3` will be after the next two sessions complete, as per our
        documentation.

        We aren't concerned about this addition failing as with sessions once per week, and
        `Session` wrapping a `u32`, this will last > 82 million years. Even if sessions were once a
        day, this would be valid for more than 11.5 million years.
      */
      let unlocks_at = Session(present_in_session.0 + 3);
      // If there's an existing deallocation, we sum to it now
      Storage::DelayedDeallocations::mutate(
        validator,
        ValidatorSet { network, session: unlocks_at },
        |delayed| {
          *delayed = Some((delayed.unwrap_or(Amount(0)) + amount).unwrap());
        },
      );
      return DeallocationTimeline::Delayed { unlocks_at };
    }

    // Because this validator wasn't present in a session which hasn't had its delay already
    // satisfied, immediately handle the deallocation
    DeallocationTimeline::Immediate
  }

  fn drain_delayed_deallocations(network: NetworkId, validator: SeraiAddress) -> Amount {
    /*
      We do not drain _all_ delayed deallocations for this validator, which may be of length equal
      to the amount of sessions which have occurred, but only the actively-delayed deallocations.

      This is supposed to be in response to a slash, and a slash should be timely such that the
      relevant stake is still _actively_ delayed.
    */
    let Some(current_session) = Storage::CurrentSession::get(network) else { return Amount(0) };
    // We first iterate to discover the keys, as mutating while iterating is undefined behavior
    let mut sets = vec![];
    for set in Storage::DelayedDeallocations::iter_key_prefix_from(
      validator,
      (ValidatorSet { network, session: current_session }).encode(),
    ) {
      // If we iterated into the following network, `break`
      if set.network != network {
        break;
      }
      sets.push(set);
    }

    // We then iterate to remove them
    let mut amount = 0;
    for set in sets {
      // We know this key exists as we just iterated to discover it
      amount += Storage::DelayedDeallocations::take(validator, set).unwrap().0;
    }
    Amount(amount)
  }

  fn claim_delayed_deallocation(
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  ) -> Result<Amount, DelayedDeallocationError> {
    if Storage::CurrentSession::get(network) < Some(session) {
      Err(DelayedDeallocationError::DelayNotSatisfied)?;
    }
    Storage::DelayedDeallocations::take(validator, ValidatorSet { network, session })
      .ok_or(DelayedDeallocationError::NoDelayedDeallocations)
  }
}
