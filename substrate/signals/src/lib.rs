#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[frame_support::pallet]
pub mod pallet {
  use sp_core::sr25519::Public;

  use serai_abi::{
    primitives::{prelude::*, signals::*},
    signals::Event,
    SubstrateBlock,
  };

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_validator_sets_pallet::{Config as VsConfig, Pallet as VsPallet};
  use serai_core_pallet::{Config as CoreConfig, Pallet as Core};

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = Public, Block = SubstrateBlock> + VsConfig + CoreConfig
  {
    /// How long a candidate retirement signal is valid for.
    ///
    /// This MUST be equal to the rate at which new sets are attempted.
    // TODO: Fetch from `validator_sets::Config`.
    type RetirementValidityDuration: Get<u64>;
    /// How long a retirement signal is locked-in for before retirement..
    type RetirementLockInDuration: Get<u64>;
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
        Assert the validity duration is less than the lock-in duration.

        This way, while the the signal is locked-in, any/all other candidate retirement signals
        will expire.
      */
      assert!(T::RetirementValidityDuration::get() < T::RetirementLockInDuration::get());
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The registered retirement signals.
  #[pallet::storage]
  type RegisteredRetirementSignals<T: Config> =
    StorageMap<_, Blake2_128Concat, [u8; 32], RegisteredRetirementSignal, OptionQuery>;

  /// The registered favors.
  #[pallet::storage]
  type Favors<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    (Signal, NetworkId),
    Blake2_128Concat,
    T::AccountId,
    (),
    OptionQuery,
  >;

  /// The networks in favor of a signal.
  #[pallet::storage]
  type NetworksInFavor<T: Config> =
    StorageMap<_, Blake2_128Concat, (Signal, NetworkId), (), OptionQuery>;

  /// The locked-in retirement signal.
  ///
  /// This is in the format `(protocol_id, retiry_block)`.
  #[pallet::storage]
  type LockedInRetirement<T: Config> =
    StorageValue<_, (ProtocolId, BlockNumberFor<T>), OptionQuery>;

  /// Halted networks.
  ///
  /// Halted networks will be halted for the remainder of this protocol's lifetime.
  #[pallet::storage]
  type Halted<T: Config> = StorageMap<_, Identity, ExternalNetworkId, (), OptionQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(current_number: BlockNumberFor<T>) -> Weight {
      /*
        If this is the block at which a locked-in retirement signal has been locked-in for long
        enough, panic, halting the blockchain, and retiring the current protocol.
      */
      if let Some((protocol_id, block_number)) = LockedInRetirement::<T>::get() {
        assert!(
          current_number < block_number,
          "protocol retired in favor of {}",
          sp_core::hexdisplay::HexDisplay::from(&protocol_id)
        );
      }
      // Using `Weight::zero()` is fine here as this is a minute operation
      Weight::zero()
    }
  }

  impl<T: Config> Pallet<T> {
    /// Tally the support for a signal by a network's current validator set.
    ///
    /// This will mutate the storage with the result.
    ///
    /// This returns `true` if the network is sufficiently in favor of the signal.
    fn tally_for_network(signal: Signal, network: NetworkId) -> bool {
      let Some(current_session) = VsPallet::<T>::current_session(network) else { return false };
      let current_set = ValidatorSet { network, session: current_session };
      let Some(latest_session) = VsPallet::<T>::latest_decided_session(network) else {
        panic!("current session yet no latest decided session")
      };
      let latest_set = ValidatorSet { network, session: latest_session };

      /*
        The following uses key shares, not allocations, as key shares are static while allocations
        fluctuate during the duration of a validator set.
      */

      let mut needed_favor = {
        let current = u16::from(
          VsPallet::<T>::key_shares(current_set)
            .expect("current validator set without key shares set"),
        );
        let latest = u16::from(
          VsPallet::<T>::key_shares(latest_set)
            .expect("latest validator set without key shares set"),
        );
        current.max(latest)
      };
      for (validator, ()) in Favors::<T>::iter_prefix((signal, network)) {
        /*
          Fetch the amount of key shares the validator has.

          This uses the minimum amount of key shares across the current validator set and the
          latest decided validator set to ensure this validator represents this network and will
          continue to do so.
        */
        let key_shares = {
          let current = VsPallet::<T>::key_shares_possessed_by_validator(current_set, validator)
            .unwrap_or(KeyShares::ZERO);
          let latest = VsPallet::<T>::key_shares_possessed_by_validator(latest_set, validator)
            .unwrap_or(KeyShares::ZERO);
          u16::from(current).min(u16::from(latest))
        };

        let Some(still_needed_favor) = needed_favor.checked_sub(key_shares) else {
          needed_favor = 0;
          break;
        };
        needed_favor = still_needed_favor;
      }

      let now_in_favor = needed_favor == 0;

      // Update the storage and emit an event, if appropriate
      if now_in_favor {
        let prior_in_favor = NetworksInFavor::<T>::contains_key((signal, network));
        NetworksInFavor::<T>::set((signal, network), Some(()));
        if !prior_in_favor {
          Core::<T>::emit_event(Event::NetworkInFavor { signal, network });
        }
      } else {
        #[allow(clippy::collapsible_else_if)] // This doesn't work with `expect`
        if NetworksInFavor::<T>::take((signal, network)).is_some() {
          Core::<T>::emit_event(Event::NetworkNoLongerInFavor { signal, network });
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
        /*
          This doesn't consider if the latest decided validator set has considerably less stake,
          yet the bound validators vote by the minimum of their key shares, against the maximum of
          the total key shares, should be sufficient in this regard.
        */
        let network_stake =
          VsPallet::<T>::stake_for_current_validator_set(network).unwrap_or(Amount(0));
        if NetworksInFavor::<T>::contains_key((signal, network)) {
          total_in_favor_stake += network_stake.0;
        }
        total_allocated_stake += network_stake.0;
      }

      /*
        We use a 80% threshold for retirement, calculated as defined above, but just a 34%
        threshold for halting another validator set. This is representative of how 34% of
        validators can cause a liveness failure during asynchronous BFT>
      */
      let threshold = match signal {
        Signal::Retire { .. } => (total_allocated_stake * 4) / 5,
        Signal::Halt { .. } => (total_allocated_stake * 2) / 3,
      };
      total_in_favor_stake > threshold
    }

    fn revoke_favor_internal(
      validator: T::AccountId,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      if !Favors::<T>::contains_key((signal, with_network), validator) {
        Err::<(), _>(Error::<T>::RevokingNonExistentFavor)?;
      }
      Favors::<T>::remove((signal, with_network), validator);
      Core::<T>::emit_event(Event::FavorRevoked { signal, by: validator.into(), with_network });

      // Update the tally for this network
      Self::tally_for_network(signal, with_network);

      Ok(())
    }

    /// Check if an external network was halted.
    pub fn halted(network: ExternalNetworkId) -> bool {
      Halted::<T>::contains_key(network)
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
    /// The caller is already in favor.
    AlreadyInFavor,
    /// Revoking favor when no favor has been expressed.
    RevokingNonExistentFavor,
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Register a retirement signal, declaring the consensus protocol this signal is in favor of.
    ///
    /// Retirement signals are registered so that the proposer, presumably a developer, can revoke
    /// the signal if there's a fault discovered.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
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
      let registrant = SeraiAddress::from(validator);
      let signal = RegisteredRetirementSignal {
        in_favor_of,
        registrant,
        registered_at: frame_system::Pallet::<T>::block_number(),
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
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn revoke_retirement_signal(
      origin: OriginFor<T>,
      retirement_signal: [u8; 32],
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(retirement_signal) else {
        return Err::<(), _>(Error::<T>::NonExistentRetirementSignal.into());
      };
      if SeraiAddress::from(validator) != registered_signal.registrant {
        Err::<(), _>(Error::<T>::NotRetirementSignalRegistrant)?;
      }
      RegisteredRetirementSignals::<T>::remove(retirement_signal);

      /*
        If this signal was locked in, remove it.

        This lets a post-lock-in discovered fault be prevented from going live without intervention
        by a supermajority of validators.
      */
      if LockedInRetirement::<T>::get().map(|(signal, _block_number)| signal) ==
        Some(retirement_signal)
      {
        LockedInRetirement::<T>::kill();
      }

      Core::<T>::emit_event(Event::RetirementSignalRevoked { signal: retirement_signal });

      Ok(())
    }

    /// Favor a signal.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn favor(origin: OriginFor<T>, signal: Signal, with_network: NetworkId) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      // Perform the relevant checks for this class of signal
      match signal {
        Signal::Retire { signal_id } => {
          // Make sure a retirement hasn't already been locked in
          if LockedInRetirement::<T>::exists() {
            Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
          }

          /*
            Make sure this is a registered retirement.

            We don't have to do this for a `Halt` signal as `Halt` doesn't have the registration
            process.
          */
          let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(signal_id) else {
            return Err::<(), _>(Error::<T>::NonExistentRetirementSignal.into());
          };

          // Check the signal isn't out of date, and its tallies with it.
          if (registered_signal.registered_at + T::RetirementValidityDuration::get()) <
            frame_system::Pallet::<T>::block_number()
          {
            Err::<(), _>(Error::<T>::ExpiredRetirementSignal)?;
          }
        }
        Signal::Halt { .. } => {}
      }

      if Favors::<T>::contains_key((signal, with_network), validator) {
        Err::<(), _>(Error::<T>::AlreadyInFavor)?;
      }

      // Set the validator as in favor
      Favors::<T>::set((signal, with_network), validator, Some(()));

      Core::<T>::emit_event(Event::SignalFavored { signal, by: validator.into(), with_network });

      // Check if the network is in favor
      let network_in_favor = Self::tally_for_network(signal, with_network);

      // If this network is in favor, check if enough networks are
      if network_in_favor && Self::tally_for_all_networks(signal) {
        // If enough are, lock in the signal
        match signal {
          Signal::Retire { signal_id } => {
            LockedInRetirement::<T>::set(Some((
              signal_id,
              frame_system::Pallet::<T>::block_number() + T::RetirementLockInDuration::get(),
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
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn revoke_favor(
      origin: OriginFor<T>,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      match signal {
        Signal::Retire { .. } => {
          if LockedInRetirement::<T>::exists() {
            Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
          }
        }
        Signal::Halt { .. } => {}
      }

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
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn stand_against(
      origin: OriginFor<T>,
      signal: Signal,
      with_network: NetworkId,
    ) -> DispatchResult {
      match signal {
        Signal::Retire { .. } => {
          if LockedInRetirement::<T>::exists() {
            Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
          }
        }
        Signal::Halt { .. } => {}
      }

      let validator = ensure_signed(origin)?;
      // If currently in favor, revoke the favor
      if Favors::<T>::contains_key((signal, with_network), validator) {
        Self::revoke_favor_internal(validator, signal, with_network)?;
      } else {
        // Check this Signal exists (which would've been implied by `Favors` for it existing)
        match signal {
          Signal::Retire { signal_id } => {
            if RegisteredRetirementSignals::<T>::get(signal_id).is_none() {
              Err::<(), _>(Error::<T>::NonExistentRetirementSignal)?;
            }
          }
          Signal::Halt { .. } => {}
        }
      }

      Core::<T>::emit_event(Event::AgainstSignal {
        signal,
        account: validator.into(),
        with_network,
      });

      Ok(())
    }
  }
}

pub use pallet::*;
