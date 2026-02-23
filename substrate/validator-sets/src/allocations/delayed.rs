use alloc::vec;

use serai_abi::primitives::{
  address::SeraiAddress,
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{Session, ValidatorSet, DeallocationTimeline},
};

use frame_support::storage::{StorageMap as _, StorageDoubleMap as _, IterableStorageDoubleMap};

/// A `trait` to access session information via.
///
/// This should be `serai_validator_sets_pallet::sessions::SessionsStorage`, which is of notable
/// complexity. We explicitly declare the subset we need here to make testing easier.
pub(crate) trait Sessions {
  fn current_session(network: NetworkId) -> Option<Session>;
  fn latest_decided_session(network: NetworkId) -> Option<Session>;
  fn in_validator_set(set: ValidatorSet, validator: SeraiAddress) -> bool;
}
impl<S: crate::sessions::SessionsStorage> Sessions for S {
  fn current_session(network: NetworkId) -> Option<Session> {
    S::CurrentSession::get(network)
  }
  fn latest_decided_session(network: NetworkId) -> Option<Session> {
    S::LatestDecidedSession::get(network)
  }
  fn in_validator_set(set: ValidatorSet, validator: SeraiAddress) -> bool {
    S::SelectedValidators::contains_key(set, validator)
  }
}

pub(crate) trait DelayedDeallocationsStorage {
  /// The interface to the sessions information.
  type Sessions: Sessions;

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
  Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking, frame_support::PalletError,
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
  fn drain_delayed_deallocations(validator: SeraiAddress, network: NetworkId) -> Amount;

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

  /// Retrieve the deallocations delayed from the specified session.
  fn fetch_deallocations_delayed_from(
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  ) -> Option<Amount>;
}

/*
  For a validator present in set #`n`, they should only be able to deallocate once set #`n+3` is
  current. This ensures at least the intended duration of a session is provided to halt further
  handovers (along with associated pending deallocations).

  We find the most recent session this validator was in (which would still be subject to a delay)
  before determining the session this deallocation should unlock at.
*/
fn find_most_recent_relevant_session_for_validator<S: Sessions>(
  network: NetworkId,
  validator: SeraiAddress,
) -> Option<Session> {
  let mut session = S::latest_decided_session(network)?;
  /*
    We check the latest decided session, current session, prior session, and prior prior
    session.

    If the prior prior session has index #0, then deallocations from validators active during
    it should only be able to claim their deallocation after session #2 has completed. As the
    current session is #2, delays from the prior prior session would still be in effect.
  */
  let sessions_to_check = 3 + u8::from(Some(session) != S::current_session(network));
  for _ in 0 .. sessions_to_check {
    // This will be pruned for historical sessions, but the sessions we check aren't historical
    // per the definition in the `Sessions` abstraction (which aligns with here)
    if S::in_validator_set(ValidatorSet { network, session }, validator) {
      return Some(session);
    }
    let Some(prior_session) = session.0.checked_sub(1) else { break };
    session = Session(prior_session);
  }
  None
}

impl<Storage: DelayedDeallocationsStorage> DelayedDeallocations for Storage {
  fn potentially_delay_deallocation(
    network: NetworkId,
    validator: SeraiAddress,
    amount: Amount,
  ) -> DeallocationTimeline {
    if let Some(present_in_session) =
      find_most_recent_relevant_session_for_validator::<Storage::Sessions>(network, validator)
    {
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

  fn drain_delayed_deallocations(validator: SeraiAddress, network: NetworkId) -> Amount {
    /*
      We do not drain _all_ delayed deallocations for this validator, which may be of length equal
      to the amount of sessions which have occurred, but only the actively-delayed deallocations
      which are bounded to be at most `3`.

      This is supposed to be in response to a slash, and a slash should be timely such that the
      relevant stake is still _actively_ delayed.
    */
    let Some(current_session) = Storage::Sessions::current_session(network) else {
      return Amount(0);
    };
    // We first iterate to discover the keys, as mutating while iterating is undefined behavior
    let mut sets = vec![];
    for set in Storage::DelayedDeallocations::iter_key_prefix_from(
      validator,
      Storage::DelayedDeallocations::hashed_key_for(
        validator,
        ValidatorSet { network, session: current_session },
      ),
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
    if Storage::Sessions::current_session(network) < Some(session) {
      Err(DelayedDeallocationError::DelayNotSatisfied)?;
    }
    Storage::DelayedDeallocations::take(validator, ValidatorSet { network, session })
      .ok_or(DelayedDeallocationError::NoDelayedDeallocations)
  }

  fn fetch_deallocations_delayed_from(
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  ) -> Option<Amount> {
    Storage::DelayedDeallocations::get(
      validator,
      ValidatorSet { network, session: Session(session.0 + 3) },
    )
  }
}

#[cfg(test)]
pub(crate) mod mock {
  use frame_support::{pallet_prelude::*, traits::StorageInstance};
  use serai_abi::primitives::{network_id::NetworkId, validator_sets::*};
  use super::*;
  use crate::MockStorage;

  pub struct CurrentSessionStorage;
  impl StorageInstance for CurrentSessionStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::CurrentSession";
  }
  pub(crate) type CurrentSession =
    StorageMap<CurrentSessionStorage, Identity, NetworkId, Session, OptionQuery>;

  pub struct LatestDecidedSessionStorage;
  impl StorageInstance for LatestDecidedSessionStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::LatestDecidedSession";
  }
  pub(crate) type LatestDecidedSession =
    StorageMap<LatestDecidedSessionStorage, Identity, NetworkId, Session, OptionQuery>;

  pub struct SelectedValidatorsStorage;
  impl StorageInstance for SelectedValidatorsStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::SelectedValidators";
  }
  pub(crate) type SelectedValidators = StorageDoubleMap<
    SelectedValidatorsStorage,
    Identity,
    ValidatorSet,
    Blake2_128Concat,
    SeraiAddress,
    (),
    OptionQuery,
  >;

  pub struct DelayedDeallocationsStorage;
  impl StorageInstance for DelayedDeallocationsStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::DelayedDeallocations";
  }
  pub(crate) type DelayedDeallocations = StorageDoubleMap<
    DelayedDeallocationsStorage,
    Blake2_128Concat,
    SeraiAddress,
    Identity,
    ValidatorSet,
    Amount,
    OptionQuery,
  >;

  impl Sessions for MockStorage {
    fn current_session(network: NetworkId) -> Option<Session> {
      CurrentSession::get(network)
    }
    fn latest_decided_session(network: NetworkId) -> Option<Session> {
      LatestDecidedSession::get(network)
    }
    fn in_validator_set(set: ValidatorSet, validator: SeraiAddress) -> bool {
      SelectedValidators::contains_key(set, validator)
    }
  }

  impl super::DelayedDeallocationsStorage for MockStorage {
    type Sessions = Self;
    type DelayedDeallocations = DelayedDeallocations;
  }
}

#[cfg(test)]
mod tests {
  use super::{
    *,
    mock::{DelayedDeallocations, *},
  };
  use crate::MockStorage;

  #[test]
  fn test_find_most_recent_relevant_session_for_validator() {
    sp_io::TestExternalities::new_empty().execute_with(|| {
      let network = NetworkId::Serai;
      let alice = SeraiAddress([0xaa; 32]);

      // Someone not present should not be considered present
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        None
      );

      // Decide the first session
      LatestDecidedSession::set(network, Some(Session(0)));
      // Alice still is not present and should not be considered present
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        None
      );
      // Add Alice
      SelectedValidators::set(ValidatorSet { network, session: Session(0) }, alice, Some(()));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(0))
      );
      CurrentSession::set(network, Some(Session(0)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(0))
      );

      // Updating the session should still yield the relevant session
      LatestDecidedSession::set(network, Some(Session(1)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(0))
      );
      CurrentSession::set(network, Some(Session(1)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(0))
      );

      // And it is the _most recent_ relevant session which should be yielded
      SelectedValidators::set(ValidatorSet { network, session: Session(1) }, alice, Some(()));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(1))
      );

      // If the latest decided session is `+ 3`, but it isn't current, this still relevant
      LatestDecidedSession::set(network, Some(Session(4)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(1))
      );
      CurrentSession::set(network, Some(Session(3)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        Some(Session(1))
      );

      // But it's no longer relevant when the current session is `+ 3`
      CurrentSession::set(network, Some(Session(4)));
      assert_eq!(
        find_most_recent_relevant_session_for_validator::<MockStorage>(network, alice),
        None
      );
    });
  }

  #[test]
  fn potentially_delay_deallocation() {
    sp_io::TestExternalities::new_empty().execute_with(|| {
      let network = NetworkId::Serai;
      let alice = SeraiAddress([0xaa; 32]);

      // Delaying the deallocation of a non-present validator should happen immediately
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::potentially_delay_deallocation(
          network,
          alice,
          Amount(1)
        ),
        DeallocationTimeline::Immediate
      );

      // Else, it should happen at `+ 3`
      LatestDecidedSession::set(network, Some(Session(0)));
      CurrentSession::set(network, Some(Session(0)));
      SelectedValidators::set(ValidatorSet { network, session: Session(0) }, alice, Some(()));
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::potentially_delay_deallocation(
          network,
          alice,
          Amount(1)
        ),
        DeallocationTimeline::Delayed { unlocks_at: Session(3) }
      );
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(3) }),
        Some(Amount(1))
      );
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
          alice,
          network,
          Session(0)
        ),
        Some(Amount(1))
      );

      // Further deallocations should be possible
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::potentially_delay_deallocation(
          network,
          alice,
          Amount(2)
        ),
        DeallocationTimeline::Delayed { unlocks_at: Session(3) }
      );
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(3) }),
        Some(Amount(3))
      );
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
          alice,
          network,
          Session(0)
        ),
        Some(Amount(3))
      );

      // Existing delayed deallocations should not affect distinctly-delayed deallocations
      LatestDecidedSession::set(network, Some(Session(1)));
      CurrentSession::set(network, Some(Session(1)));
      SelectedValidators::set(ValidatorSet { network, session: Session(1) }, alice, Some(()));
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::potentially_delay_deallocation(
          network,
          alice,
          Amount(5)
        ),
        DeallocationTimeline::Delayed { unlocks_at: Session(4) }
      );
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(3) }),
        Some(Amount(3))
      );
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
          alice,
          network,
          Session(0)
        ),
        Some(Amount(3))
      );
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(4) }),
        Some(Amount(5))
      );
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
          alice,
          network,
          Session(1)
        ),
        Some(Amount(5))
      );
    });
  }

  #[test]
  fn drain_delayed_deallocations() {
    use sp_core::Decode as _;
    sp_io::TestExternalities::new_empty().execute_with(|| {
      let prior_network = NetworkId::decode(&mut [0].as_slice()).unwrap();
      let network = NetworkId::decode(&mut [1].as_slice()).unwrap();
      let following_network = NetworkId::decode(&mut [2].as_slice()).unwrap();

      let alice = SeraiAddress([0xaa; 32]);

      // If nothing has happened, this should return `0`
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::drain_delayed_deallocations(alice, network),
        Amount(0)
      );

      LatestDecidedSession::set(network, Some(Session(4)));
      CurrentSession::set(network, Some(Session(3)));

      // Set delayed deallocations for the prior/following network to ensure we only iterate
      // within a network
      DelayedDeallocations::set(
        alice,
        ValidatorSet { network: prior_network, session: Session(4) },
        Some(Amount(u64::MAX >> 1)),
      );
      DelayedDeallocations::set(
        alice,
        ValidatorSet { network: following_network, session: Session(4) },
        Some(Amount(u64::MAX >> 2)),
      );

      // Deallocations aren't _actively_ delayed should not be considered
      DelayedDeallocations::set(
        alice,
        ValidatorSet { network, session: Session(3) },
        Some(Amount(u64::MAX >> 3)),
      );

      // If there no deallocations, this should return `0`
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::drain_delayed_deallocations(alice, network),
        Amount(0)
      );

      // Add multiple _actively_ delayed deallocations
      DelayedDeallocations::set(
        alice,
        ValidatorSet { network, session: Session(4) },
        Some(Amount(1)),
      );
      DelayedDeallocations::set(
        alice,
        ValidatorSet { network, session: Session(5) },
        Some(Amount(2)),
      );

      // Draining these should work
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::drain_delayed_deallocations(alice, network),
        Amount(3)
      );

      // The storage should be unchanged for irrelevant delayed deallocations
      assert_eq!(
        DelayedDeallocations::get(
          alice,
          ValidatorSet { network: prior_network, session: Session(4) }
        ),
        Some(Amount(u64::MAX >> 1))
      );
      assert_eq!(
        DelayedDeallocations::get(
          alice,
          ValidatorSet { network: following_network, session: Session(4) }
        ),
        Some(Amount(u64::MAX >> 2))
      );
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(3) }),
        Some(Amount(u64::MAX >> 3))
      );
      // But the delayed ones should be taken
      assert!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(4) }).is_none()
      );
      assert!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(5) }).is_none()
      );
      assert!(<MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
        alice,
        network,
        Session(1)
      )
      .is_none());
      assert!(<MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
        alice,
        network,
        Session(2)
      )
      .is_none());
    });
  }

  #[test]
  fn claim_delayed_deallocation() {
    sp_io::TestExternalities::new_empty().execute_with(|| {
      let network = NetworkId::Serai;
      let alice = SeraiAddress([0xaa; 32]);

      LatestDecidedSession::set(network, Some(Session(3)));
      CurrentSession::set(network, Some(Session(3)));

      assert!(matches!(
        <MockStorage as super::DelayedDeallocations>::claim_delayed_deallocation(
          alice,
          network,
          Session(3)
        ),
        Err(DelayedDeallocationError::NoDelayedDeallocations)
      ));

      DelayedDeallocations::set(
        alice,
        ValidatorSet { network, session: Session(4) },
        Some(Amount(1)),
      );

      // We should not be able to claim this before this is the current session
      assert!(matches!(
        <MockStorage as super::DelayedDeallocations>::claim_delayed_deallocation(
          alice,
          network,
          Session(4)
        ),
        Err(DelayedDeallocationError::DelayNotSatisfied)
      ));
      // This call, which errored, should not modify the storage
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(4) }),
        Some(Amount(1))
      );

      // Being the latest decided session is insufficient
      LatestDecidedSession::set(network, Some(Session(4)));
      assert!(matches!(
        <MockStorage as super::DelayedDeallocations>::claim_delayed_deallocation(
          alice,
          network,
          Session(4)
        ),
        Err(DelayedDeallocationError::DelayNotSatisfied)
      ));
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(4) }),
        Some(Amount(1))
      );

      // It should work when this is the current session
      CurrentSession::set(network, Some(Session(4)));
      assert_eq!(
        <MockStorage as super::DelayedDeallocations>::claim_delayed_deallocation(
          alice,
          network,
          Session(4)
        )
        .unwrap(),
        Amount(1)
      );
      // It should consume the storage, preventing this from being called again
      assert_eq!(
        DelayedDeallocations::get(alice, ValidatorSet { network, session: Session(4) }),
        None
      );
      assert!(<MockStorage as super::DelayedDeallocations>::fetch_deallocations_delayed_from(
        alice,
        network,
        Session(1)
      )
      .is_none());
      assert!(matches!(
        <MockStorage as super::DelayedDeallocations>::claim_delayed_deallocation(
          alice,
          network,
          Session(4)
        ),
        Err(DelayedDeallocationError::NoDelayedDeallocations)
      ));
    });
  }
}
