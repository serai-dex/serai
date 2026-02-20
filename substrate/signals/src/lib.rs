#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

mod registered_retirement_signal;

#[cfg(test)]
mod tests;

/// The utilities for benchmarking this pallet.
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

use serai_abi::primitives::{
  address::SeraiAddress,
  network_id::NetworkId,
  balance::Amount,
  validator_sets::{Session, ValidatorSet, KeyShares},
};

pub(crate) mod sealed {
  #[doc(hidden)]
  pub trait Sealed {}
}
/// Loosely bind to `serai-validator-sets-pallet` so we may shim it when testing.
pub trait ValidatorSets: sealed::Sealed {
  /// Fetch the current session for the specified network.
  ///
  /// For `NetworkId::Serai`, this MUST return `Some(_)`. By virtue of this blockchain existing,
  /// there must be a Serai validator set.
  fn current_session(network: NetworkId) -> Option<Session>;
  /// The amount of key shares (or weight in consensus) for the specified validator set.
  ///
  /// This MUST NOT return `None` for a current validator set.
  fn key_shares(set: ValidatorSet) -> Option<KeyShares>;
  /// The selected validators, and their key shares, for the specified validator set.
  ///
  /// This is allowed to have undefined behavior if called for a validator set which isn't current.
  fn selected_validators(set: ValidatorSet) -> impl Iterator<Item = (SeraiAddress, KeyShares)>;
  /// The stake (in `Coin::Serai`) for the current validator set for the specified network.
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount>;
}

impl<T: serai_validator_sets_pallet::Config> sealed::Sealed
  for serai_validator_sets_pallet::Pallet<T>
{
}
impl<T: serai_validator_sets_pallet::Config> ValidatorSets
  for serai_validator_sets_pallet::Pallet<T>
{
  fn current_session(network: NetworkId) -> Option<Session> {
    serai_validator_sets_pallet::Pallet::<T>::current_session(network)
  }
  fn key_shares(set: ValidatorSet) -> Option<KeyShares> {
    serai_validator_sets_pallet::Pallet::<T>::key_shares(set)
  }
  fn selected_validators(set: ValidatorSet) -> impl Iterator<Item = (SeraiAddress, KeyShares)> {
    serai_validator_sets_pallet::Pallet::<T>::selected_validators(set)
  }
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    serai_validator_sets_pallet::Pallet::<T>::stake_for_current_validator_set(network)
  }
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[frame_support::pallet]
pub mod pallet {
  use serai_abi::{
    primitives::{prelude::*, signals::*},
    signals::Event,
  };

  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use serai_core_pallet::{Config as CoreConfig, Pallet as Core};

  use super::{registered_retirement_signal::*, *};

  /// The weights for the calls within this pallet.
  pub trait Weights {
    /// The weight for [`Call::register_retirement_signal`].
    fn register_retirement_signal() -> Weight;
    /// The weight for [`Call::revoke_retirement_signal`].
    fn revoke_retirement_signal() -> Weight;
    /// The weight for [`Call::favor`].
    fn favor() -> Weight;
    /// The weight for [`Call::revoke_favor`].
    fn revoke_favor() -> Weight;
    /// The weight for [`Call::stand_against`].
    fn stand_against() -> Weight;
  }

  /// A shimmed set of weights, returning zero.
  ///
  /// This is NOT safe for usage in a production system and is provided only for testing purposes.
  impl Weights for () {
    fn register_retirement_signal() -> Weight {
      Weight::zero()
    }
    fn revoke_retirement_signal() -> Weight {
      Weight::zero()
    }
    fn favor() -> Weight {
      Weight::zero()
    }
    fn revoke_favor() -> Weight {
      Weight::zero()
    }
    fn stand_against() -> Weight {
      Weight::zero()
    }
  }

  #[pallet::config]
  pub trait Config: frame_system::Config + pallet_babe::Config + CoreConfig {
    /// How long a retirement signal is locked-in for before retirement.
    type RetirementLockInDurationInSlots: Get<u64>;
    /// The validator sets pallet.
    type ValidatorSets: ValidatorSets;

    /// The weights to use for this pallet's [`Call`].
    type Weights: Weights;
  }

  #[pallet::genesis_config]
  #[derive(Clone, Debug)]
  pub struct GenesisConfig<T: Config> {
    _config: PhantomData<T>,
  }
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      Self { _config: PhantomData }
    }
  }
  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      /*
        Assert the duration for which retirement signals are valid is less than the lock-in
        duration. This way, while the the signal is locked-in, any/all other candidate retirement
        signals will expire.

        It's `2 *` as the latest-decided Serai session must become current, and then become prior,
        for the retirement signal's lifetime to expire.
      */
      assert!((2 * T::EpochDuration::get()) < T::RetirementLockInDurationInSlots::get());
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The registered retirement signals.
  #[pallet::storage]
  #[pallet::unbounded]
  type RegisteredRetirementSignals<T: Config> =
    StorageMap<_, Blake2_128Concat, [u8; 32], RegisteredRetirementSignal, OptionQuery>;

  /// The registered favors.
  ///
  /// The value is the Serai session this favor is valid until (inclusive).
  #[pallet::storage]
  type Favors<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    (Signal, NetworkId),
    Blake2_128Concat,
    T::AccountId,
    Session,
    OptionQuery,
  >;

  /// The validator sets in favor of a signal.
  #[pallet::storage]
  type ValidatorSetsInFavor<T: Config> =
    StorageMap<_, Blake2_128Concat, (Signal, ValidatorSet), (), OptionQuery>;

  /// The locked-in retirement signal.
  ///
  /// This is in the format `(protocol_id, retiry_slot)`.
  #[pallet::storage]
  type LockedInRetirement<T: Config> = StorageValue<_, (ProtocolId, u64), OptionQuery>;

  /// Halted networks.
  ///
  /// Halted networks will be halted for the remainder of this protocol's lifetime.
  #[pallet::storage]
  type Halted<T: Config> = StorageMap<_, Identity, ExternalNetworkId, (), OptionQuery>;

  #[pallet::hooks] // serai-core-pallet: allow
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(_current_block_number: BlockNumberFor<T>) -> Weight {
      /*
        If this is the block at which a locked-in retirement signal has been locked-in for long
        enough, panic, halting the blockchain, and retiring the current protocol.
      */
      if let Some((protocol_id, end_slot)) = LockedInRetirement::<T>::get() {
        assert!(
          (*pallet_babe::Pallet::<T>::current_slot()) < end_slot,
          "protocol retired in favor of {}",
          sp_core::hexdisplay::HexDisplay::from(&protocol_id)
        );
      }
      // Using `Weight::zero()` is fine here as this is a minute operation
      Weight::zero()
    }
  }

  /// An error from the `signals` pallet.
  #[pallet::error]
  pub enum Error<T> {
    /// A retirement signal has already been locked in.
    RetirementSignalLockedIn,
    /// This retirement signal has already been registered.
    RetirementSignalAlreadyRegistered,
    /// The caller is not the registrant of the retirement signal.
    NotRetirementSignalRegistrant,
    /// The retirement signal does not exist.
    NonExistentRetirementSignal,
    /// The retirement signal has expired.
    ExpiredRetirementSignal,
    /// Revoking favor when no favor has been expressed.
    RevokingNonExistentFavor,
  }

  impl<T: Config> Pallet<T> {
    fn current_serai_session() -> Session {
      T::ValidatorSets::current_session(NetworkId::Serai).expect("no current session for Serai?")
    }

    /// Perform the relevant checks for this class of signal.
    fn validate_signal(signal: &Signal) -> Result<(), Error<T>> {
      match signal {
        Signal::Retire { signal_id } => {
          // Make sure a retirement hasn't already been locked in
          if LockedInRetirement::<T>::exists() {
            Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
          }

          /*
            Make sure this is a registered retirement signal.

            We don't have to do this for a `Halt` signal as `Halt` doesn't have the registration
            process.
          */
          let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(signal_id) else {
            return Err::<(), _>(Error::<T>::NonExistentRetirementSignal);
          };

          // Make sure this signal hasn't expired
          if Session(registered_signal.registered_at.0 + 2) <= Self::current_serai_session() {
            return Err::<(), _>(Error::<T>::ExpiredRetirementSignal);
          }
        }
        Signal::Halt { .. } => {}
      }

      Ok(())
    }

    /// The required threshold which must favor this signal.
    ///
    /// We use a 80% threshold for retirement, but just a 34% threshold for halting another
    /// validator set. This is representative of how 34% of validators can cause a liveness failure
    /// during asynchronous BFT.
    fn required_threshold(signal: &Signal, amount: u64) -> u64 {
      (match signal {
        Signal::Retire { .. } => {
          u64::try_from((u128::from(amount) * 4) / 5).expect("u64::MAX * 4 / 5 < u64::MAX")
        }
        Signal::Halt { .. } => amount / 3,
      }) + 1
    }

    /// Tally the support for a signal by a network's current validator set.
    ///
    /// This will mutate the storage with the resulting tally.
    ///
    /// This returns `true` if the network is sufficiently in favor of the signal.
    fn tally_for_network(signal: Signal, network: NetworkId) -> bool {
      let Some(session) = T::ValidatorSets::current_session(network) else {
        return false;
      };
      let validator_set = ValidatorSet { network, session };

      let serai_session = Self::current_serai_session();

      /*
        The following uses key shares, not allocations, as key shares are static while allocations
        fluctuate during the duration of a validator set. It also is still representative of the
        validators proportionality to each other.
      */

      let mut needed_favor = Self::required_threshold(
        &signal,
        u64::from(u16::from(
          T::ValidatorSets::key_shares(validator_set)
            .expect("latest validator set without key shares set"),
        )),
      );
      for (validator, key_shares) in T::ValidatorSets::selected_validators(validator_set) {
        let Some(favor_until_serai_session) = Favors::<T>::get((signal, network), validator) else {
          continue;
        };
        if favor_until_serai_session < serai_session {
          continue;
        }

        let Some(still_needed_favor) = needed_favor.checked_sub(u64::from(u16::from(key_shares)))
        else {
          needed_favor = 0;
          break;
        };
        needed_favor = still_needed_favor;
      }

      let now_in_favor = needed_favor == 0;

      // Update the storage and emit an event, if appropriate
      if now_in_favor {
        let prior_in_favor = ValidatorSetsInFavor::<T>::contains_key((signal, validator_set));
        ValidatorSetsInFavor::<T>::set((signal, validator_set), Some(()));
        if !prior_in_favor {
          Core::<T>::emit_event(Event::ValidatorSetInFavor { signal, set: validator_set });
        }
      } else {
        #[expect(clippy::collapsible_else_if)]
        if ValidatorSetsInFavor::<T>::take((signal, validator_set)).is_some() {
          Core::<T>::emit_event(Event::ValidatorSetNoLongerInFavor { signal, set: validator_set });
        }
      }

      now_in_favor
    }

    /// Tally support for a signal across all networks, weighted by stake.
    ///
    /// Returns `true` if the signal has sufficient support.
    fn tally_for_all_networks(signal: Signal) -> bool {
      let mut total_in_favor_stake = 0;
      let mut total_allocated_stake = 0;
      for network in NetworkId::all() {
        let Some(session) = T::ValidatorSets::current_session(network) else {
          continue;
        };
        let validator_set = ValidatorSet { network, session };

        let network_stake =
          T::ValidatorSets::stake_for_current_validator_set(validator_set.network)
            .unwrap_or(Amount(0));
        if ValidatorSetsInFavor::<T>::contains_key((signal, validator_set)) {
          total_in_favor_stake += network_stake.0;
        }
        total_allocated_stake += network_stake.0;
      }
      total_in_favor_stake >= Self::required_threshold(&signal, total_allocated_stake)
    }

    /// Revoke a validator's favor for a network.
    ///
    /// This function is not atomic in that it may update the storage even if it returns an error.
    /// Any storage updates will be well-defined and not lead to corruption however, making the
    /// only observable effect the difference in the trie.
    fn revoke_favor_internal(
      validator: T::AccountId,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      Self::validate_signal(&signal)?;

      if Favors::<T>::take((signal, with_network), validator) < Some(Self::current_serai_session())
      {
        // Stale favor is not considered to exist
        Err::<(), _>(Error::<T>::RevokingNonExistentFavor)?;
      }
      Core::<T>::emit_event(Event::FavorRevoked { signal, by: validator, with_network });

      // Update the tally for this network
      Self::tally_for_network(signal, with_network);

      Ok(())
    }

    /// Check if an external network was halted.
    pub fn halted(network: ExternalNetworkId) -> bool {
      Halted::<T>::contains_key(network)
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Register a retirement signal, declaring the consensus protocol this signal is in favor of.
    ///
    /// Retirement signals are registered so that the proposer, presumably a developer, can revoke
    /// the signal if there's a fault discovered.
    #[pallet::call_index(0)]
    #[pallet::weight((<T as Config>::Weights::register_retirement_signal(), DispatchClass::Normal))]
    pub fn register_retirement_signal(
      origin: OriginFor<T>,
      in_favor_of: [u8; 32],
    ) -> DispatchResult {
      // Don't allow retirement signals to be registered once a retirement has been locked in
      if LockedInRetirement::<T>::exists() {
        Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
      }

      let validator = ensure_signed(origin)?;

      /*
        Bind the signal ID to the proposer.

        This prevents a malicious actor from frontrunning a proposal, causing them to be the
        registrant, just to cancel it later.
      */
      let registrant = validator;
      let current_serai_session = Self::current_serai_session();
      let signal = RegisteredRetirementSignal {
        registrant,
        in_favor_of,
        registered_at: current_serai_session,
      };
      let signal_id = signal.id();

      if RegisteredRetirementSignals::<T>::get(signal_id).is_some() {
        Err::<(), _>(Error::<T>::RetirementSignalAlreadyRegistered)?;
      }
      RegisteredRetirementSignals::<T>::set(signal_id, Some(signal));

      Core::<T>::emit_event(Event::RetirementSignalRegistered {
        signal: signal_id,
        in_favor_of,
        registrant,
      });

      Ok(())
    }

    /// Revoke a retirement signal.
    #[pallet::call_index(1)]
    #[pallet::weight((<T as Config>::Weights::revoke_retirement_signal(), DispatchClass::Normal))]
    pub fn revoke_retirement_signal(
      origin: OriginFor<T>,
      retirement_signal: [u8; 32],
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(retirement_signal) else {
        return Err::<(), _>(Error::<T>::NonExistentRetirementSignal.into());
      };
      if validator != registered_signal.registrant {
        Err::<(), _>(Error::<T>::NotRetirementSignalRegistrant)?;
      }
      RegisteredRetirementSignals::<T>::remove(retirement_signal);

      /*
        If this signal was locked in, remove it.

        This lets a post-lock-in discovered fault be prevented from going live without intervention
        by a supermajority of validators.
      */
      if LockedInRetirement::<T>::get().map(|(signal, _end_slot)| signal) == Some(retirement_signal)
      {
        LockedInRetirement::<T>::kill();
      }

      Core::<T>::emit_event(Event::RetirementSignalRevoked { signal: retirement_signal });

      Ok(())
    }

    /// Favor a signal.
    #[pallet::call_index(2)]
    #[pallet::weight((<T as Config>::Weights::favor(), DispatchClass::Normal))]
    pub fn favor(origin: OriginFor<T>, signal: Signal, with_network: NetworkId) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      Self::validate_signal(&signal)?;

      let current_serai_session = Self::current_serai_session();
      let favor_until_serai_session = Session(current_serai_session.0 + 1);

      // Set the validator as in favor
      Favors::<T>::set((signal, with_network), validator, Some(favor_until_serai_session));

      Core::<T>::emit_event(Event::SignalFavored { signal, by: validator, with_network });

      // Check if the network is in favor
      let network_in_favor = Self::tally_for_network(signal, with_network);

      // If this network is in favor, check if enough networks are
      if network_in_favor && Self::tally_for_all_networks(signal) {
        // If enough are, lock in the signal
        match signal {
          Signal::Retire { signal_id } => {
            LockedInRetirement::<T>::set(Some((
              signal_id,
              (*pallet_babe::Pallet::<T>::current_slot()) +
                T::RetirementLockInDurationInSlots::get(),
            )));
            Core::<T>::emit_event(Event::RetirementSignalLockedIn { signal: signal_id });
          }
          Signal::Halt(network) => {
            Halted::<T>::set(network, Some(()));
            Core::<T>::emit_event(Event::NetworkHalted { network });
          }
        }
      }

      Ok(())
    }

    /// Revoke favor into an abstaining position.
    #[pallet::call_index(3)]
    #[pallet::weight((<T as Config>::Weights::revoke_favor(), DispatchClass::Normal))]
    pub fn revoke_favor(
      origin: OriginFor<T>,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      Self::revoke_favor_internal(validator, signal, with_network)
    }

    /// Emit an event standing against the signal.
    ///
    /// While disapprovals aren't tracked explicitly, this is used to at least label a validator's
    /// opinion and allow better collection of data.
    ///
    /// If the origin is currently in favor of the signal, their favor will be revoked.
    #[pallet::call_index(4)]
    #[pallet::weight((<T as Config>::Weights::stand_against(), DispatchClass::Normal))]
    pub fn stand_against(
      origin: OriginFor<T>,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      // If currently in favor, revoke the favor
      if Favors::<T>::contains_key((signal, with_network), validator) {
        Self::revoke_favor_internal(validator, signal, with_network)?;
      } else {
        // If not checked with a call to `revoke_favor_internal`, check the signal's validity here
        Self::validate_signal(&signal)?;
      }

      Core::<T>::emit_event(Event::AgainstSignal { signal, account: validator, with_network });

      Ok(())
    }
  }
}

pub use pallet::{Config, GenesisConfig, Error, Pallet, Call, Weights};
#[doc(hidden)]
pub use pallet::*;
