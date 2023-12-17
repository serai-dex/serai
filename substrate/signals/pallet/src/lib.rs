#![cfg_attr(not(feature = "std"), no_std)]

#[allow(
  deprecated,
  clippy::let_unit_value,
  clippy::cast_possible_truncation,
  clippy::ignored_unit_patterns
)] // TODO
#[frame_support::pallet]
pub mod pallet {
  use scale_info::TypeInfo;

  use sp_core::sr25519::Public;
  use sp_io::hashing::blake2_256;

  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, sp_runtime};

  use serai_primitives::*;
  use serai_signals_primitives::SignalId;
  use validator_sets_pallet::{primitives::ValidatorSet, Config as VsConfig, Pallet as VsPallet};
  use in_instructions_pallet::{Config as IiConfig, Pallet as InInstructions};

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = Public> + VsConfig + IiConfig + TypeInfo
  {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;

    type RetirementValidityDuration: Get<u32>;
    type RetirementLockInDuration: Get<u32>;
  }

  #[pallet::genesis_config]
  #[derive(Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    _config: PhantomData<T>,
  }
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { _config: PhantomData }
    }
  }
  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      // Assert the validity duration is less than the lock-in duration so lock-in periods
      // automatically invalidate other retirement signals
      assert!(T::RetirementValidityDuration::get() < T::RetirementLockInDuration::get());
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
  pub struct RegisteredRetirementSignal<T: Config> {
    in_favor_of: [u8; 32],
    registrant: T::AccountId,
    registered_at: BlockNumberFor<T>,
  }

  impl<T: Config> RegisteredRetirementSignal<T> {
    fn id(&self) -> [u8; 32] {
      let mut preimage = b"Signal".to_vec();
      preimage.extend(&self.encode());
      blake2_256(&preimage)
    }
  }

  #[pallet::storage]
  type RegisteredRetirementSignals<T: Config> =
    StorageMap<_, Blake2_128Concat, [u8; 32], RegisteredRetirementSignal<T>, OptionQuery>;

  #[pallet::storage]
  pub type Favors<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    (SignalId, NetworkId),
    Blake2_128Concat,
    T::AccountId,
    (),
    OptionQuery,
  >;

  #[pallet::storage]
  pub type SetsInFavor<T: Config> =
    StorageMap<_, Blake2_128Concat, (SignalId, ValidatorSet), (), OptionQuery>;

  #[pallet::storage]
  pub type LockedInRetirement<T: Config> =
    StorageValue<_, ([u8; 32], BlockNumberFor<T>), OptionQuery>;

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    RetirementSignalRegistered {
      signal_id: [u8; 32],
      in_favor_of: [u8; 32],
      registrant: T::AccountId,
    },
    RetirementSignalRevoked {
      signal_id: [u8; 32],
    },
    SignalFavored {
      signal_id: SignalId,
      by: T::AccountId,
      for_network: NetworkId,
    },
    SetInFavor {
      signal_id: SignalId,
      set: ValidatorSet,
    },
    RetirementSignalLockedIn {
      signal_id: [u8; 32],
    },
    SetNoLongerInFavor {
      signal_id: SignalId,
      set: ValidatorSet,
    },
    FavorRevoked {
      signal_id: SignalId,
      by: T::AccountId,
      for_network: NetworkId,
    },
    AgainstSignal {
      signal_id: SignalId,
      who: T::AccountId,
      for_network: NetworkId,
    },
  }

  #[pallet::error]
  pub enum Error<T> {
    RetirementSignalLockedIn,
    RetirementSignalAlreadyRegistered,
    NotRetirementSignalRegistrant,
    NonExistentRetirementSignal,
    ExpiredRetirementSignal,
    NotValidator,
    RevokingNonExistentFavor,
  }

  // 80% threshold
  const REQUIREMENT_NUMERATOR: u64 = 4;
  const REQUIREMENT_DIVISOR: u64 = 5;

  impl<T: Config> Pallet<T> {
    // Returns true if this network's current set is in favor of the signal.
    //
    // Must only be called for networks which have a set decided.
    fn tally_for_network(signal_id: SignalId, network: NetworkId) -> bool {
      let this_network_session = VsPallet::<T>::latest_decided_session(network).unwrap();
      let this_set = ValidatorSet { network, session: this_network_session };

      // This is a bounded O(n) (which is still acceptable) due to the infeasibility of caching
      // here
      // TODO: Make caching feasible? Do a first-pass with cache then actual pass before
      // execution?
      let mut iter = Favors::<T>::iter_prefix_values((signal_id, network));
      let mut needed_favor = (VsPallet::<T>::total_allocated_stake(network).unwrap().0 *
        REQUIREMENT_NUMERATOR)
        .div_ceil(REQUIREMENT_DIVISOR);
      while iter.next().is_some() && (needed_favor != 0) {
        let item_key = iter.last_raw_key();
        // `.len() - 32` is safe because AccountId is bound to being Public, which is 32 bytes
        let account = T::AccountId::decode(&mut &item_key[(item_key.len() - 32) ..]).unwrap();
        if VsPallet::<T>::in_latest_decided_set(network, account) {
          // This call uses the current allocation, not the allocation at the time of set
          // decision
          // This is deemed safe due to the validator-set pallet's deallocation scheduling
          // unwrap is safe due to being in the latest decided set
          needed_favor =
            needed_favor.saturating_sub(VsPallet::<T>::allocation((network, account)).unwrap().0);
        }
      }

      if needed_favor == 0 {
        // Set the set as in favor until someone triggers a re-tally
        //
        // Since a re-tally is an extra step we can't assume will occur, this effectively means a
        // network in favor across any point in its Session is in favor for its entire Session
        // While a malicious actor could increase their stake, favor a signal, then deallocate,
        // this is largely prevented by deallocation scheduling
        //
        // At any given point, only just under 50% of a set can be immediately deallocated
        // (if each validator has just under two key shares, they can deallocate the entire amount
        // above a single key share)
        //
        // This means that if a signal has a 67% adoption threshold, and someone executes this
        // attack, they still have a majority of the allocated stake (though less of a majority
        // than desired)
        //
        // With the 80% threshold, removing 39.9% creates a 40.1% to 20% ratio, which is still
        // the BFT threshold of 67%
        if !SetsInFavor::<T>::contains_key((signal_id, this_set)) {
          SetsInFavor::<T>::set((signal_id, this_set), Some(()));
          Self::deposit_event(Event::SetInFavor { signal_id, set: this_set });
        }
        true
      } else {
        if SetsInFavor::<T>::contains_key((signal_id, this_set)) {
          // This should no longer be under the current tally
          SetsInFavor::<T>::remove((signal_id, this_set));
          Self::deposit_event(Event::SetNoLongerInFavor { signal_id, set: this_set });
        }
        false
      }
    }

    fn tally_for_all_networks(signal_id: SignalId) -> bool {
      let mut total_in_favor_stake = 0;
      let mut total_allocated_stake = 0;
      for network in serai_primitives::NETWORKS {
        let Some(latest_decided_session) = VsPallet::<T>::latest_decided_session(network) else {
          continue;
        };
        // If it has a session, it should have a total allocated stake value
        let network_stake = VsPallet::<T>::total_allocated_stake(network).unwrap();
        if SetsInFavor::<T>::contains_key((
          signal_id,
          ValidatorSet { network, session: latest_decided_session },
        )) {
          total_in_favor_stake += network_stake.0;
        }
        total_allocated_stake += network_stake.0;
      }

      total_in_favor_stake >=
        (total_allocated_stake * REQUIREMENT_NUMERATOR).div_ceil(REQUIREMENT_DIVISOR)
    }

    fn revoke_favor_internal(
      account: T::AccountId,
      signal_id: SignalId,
      for_network: NetworkId,
    ) -> DispatchResult {
      if !Favors::<T>::contains_key((signal_id, for_network), account) {
        Err::<(), _>(Error::<T>::RevokingNonExistentFavor)?;
      }
      Favors::<T>::remove((signal_id, for_network), account);
      Self::deposit_event(Event::<T>::FavorRevoked { signal_id, by: account, for_network });
      // tally_for_network assumes the network is active, which is implied by having prior set a
      // favor for it
      // Technically, this tally may make the network in favor and justify re-tallying for all
      // networks
      // Its assumed not to
      Self::tally_for_network(signal_id, for_network);
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Register a retirement signal, declaring the consensus protocol this signal is in favor of.
    ///
    /// Retirement signals are registered so that the proposer, presumably a developer, can revoke
    /// the signal if there's a fault discovered.
    #[pallet::call_index(0)]
    #[pallet::weight(0)] // TODO
    pub fn register_retirement_signal(
      origin: OriginFor<T>,
      in_favor_of: [u8; 32],
    ) -> DispatchResult {
      // Don't allow retirement signals to be registered once a retirement has been locked in
      if LockedInRetirement::<T>::exists() {
        Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
      }

      let account = ensure_signed(origin)?;

      // Bind the signal ID to the proposer
      // This prevents a malicious actor from frontrunning a proposal, causing them to be the
      // registrant, just to cancel it later
      let signal = RegisteredRetirementSignal {
        in_favor_of,
        registrant: account,
        registered_at: frame_system::Pallet::<T>::block_number(),
      };
      let signal_id = signal.id();

      if RegisteredRetirementSignals::<T>::get(signal_id).is_some() {
        Err::<(), _>(Error::<T>::RetirementSignalAlreadyRegistered)?;
      }

      Self::deposit_event(Event::<T>::RetirementSignalRegistered {
        signal_id,
        in_favor_of,
        registrant: account,
      });
      RegisteredRetirementSignals::<T>::set(signal_id, Some(signal));
      Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(0)] // TODO
    pub fn revoke_retirement_signal(
      origin: OriginFor<T>,
      retirement_signal_id: [u8; 32],
    ) -> DispatchResult {
      let account = ensure_signed(origin)?;
      let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(retirement_signal_id)
      else {
        return Err::<(), _>(Error::<T>::NonExistentRetirementSignal.into());
      };
      if account != registered_signal.registrant {
        Err::<(), _>(Error::<T>::NotRetirementSignalRegistrant)?;
      }
      RegisteredRetirementSignals::<T>::remove(retirement_signal_id);

      // If this signal was locked in, remove it
      // This lets a post-lock-in discovered fault be prevented from going live without
      // intervention by all validators
      if LockedInRetirement::<T>::get().map(|(signal_id, _block_number)| signal_id) ==
        Some(retirement_signal_id)
      {
        LockedInRetirement::<T>::kill();
      }

      Self::deposit_event(Event::<T>::RetirementSignalRevoked { signal_id: retirement_signal_id });
      Ok(())
    }

    #[pallet::call_index(2)]
    #[pallet::weight(0)] // TODO
    pub fn favor(
      origin: OriginFor<T>,
      signal_id: SignalId,
      for_network: NetworkId,
    ) -> DispatchResult {
      let account = ensure_signed(origin)?;

      // If this is a retirement signal, perform the relevant checks
      if let SignalId::Retirement(signal_id) = signal_id {
        // Make sure a retirement hasn't already been locked in
        if LockedInRetirement::<T>::exists() {
          Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
        }

        // Make sure this is a registered retirement
        // We don't have to do this for a `Halt` signal as `Halt` doesn't have the registration
        // process
        let Some(registered_signal) = RegisteredRetirementSignals::<T>::get(signal_id) else {
          return Err::<(), _>(Error::<T>::NonExistentRetirementSignal.into());
        };

        // Check the signal isn't out of date
        // This isn't truly necessary since we only track votes from the most recent validator
        // sets, ensuring modern relevancy
        // The reason to still have it is because locking in a dated runtime may cause a corrupt
        // blockchain and lead to a failure in system integrity
        // `Halt`, which doesn't have this check, at worst causes temporary downtime
        if (registered_signal.registered_at + T::RetirementValidityDuration::get().into()) <
          frame_system::Pallet::<T>::block_number()
        {
          Err::<(), _>(Error::<T>::ExpiredRetirementSignal)?;
        }
      }

      // Check the signer is a validator
      // Technically, in the case of Serai, this will check they're planned to be in the next set,
      // not that they are in the current set
      // This is a practical requirement due to the lack of tracking historical allocations, and
      // fine for the purposes here
      if !VsPallet::<T>::in_latest_decided_set(for_network, account) {
        Err::<(), _>(Error::<T>::NotValidator)?;
      }

      // Set them as in-favor
      // Doesn't error if they already voted in order to let any validator trigger a re-tally
      if !Favors::<T>::contains_key((signal_id, for_network), account) {
        Favors::<T>::set((signal_id, for_network), account, Some(()));
        Self::deposit_event(Event::SignalFavored { signal_id, by: account, for_network });
      }

      // Check if the network is in favor
      // tally_for_network expects the network to be active, which is implied by being in the
      // latest decided set
      let network_in_favor = Self::tally_for_network(signal_id, for_network);

      // If this network is in favor, check if enough networks are
      // We could optimize this by only running the following code when the network is *newly* in
      // favor
      // Re-running the following code ensures that if networks' allocated stakes change relative
      // to each other, any new votes will cause a re-tally
      if network_in_favor {
        // If enough are, lock in the signal
        if Self::tally_for_all_networks(signal_id) {
          match signal_id {
            SignalId::Retirement(signal_id) => {
              LockedInRetirement::<T>::set(Some((
                signal_id,
                frame_system::Pallet::<T>::block_number() +
                  T::RetirementLockInDuration::get().into(),
              )));
              Self::deposit_event(Event::RetirementSignalLockedIn { signal_id });
            }
            SignalId::Halt(network) => {
              InInstructions::<T>::halt(network)?;
            }
          }
        }
      }

      Ok(())
    }

    /// Revoke favor into an abstaining position.
    #[pallet::call_index(3)]
    #[pallet::weight(0)] // TODO
    pub fn revoke_favor(
      origin: OriginFor<T>,
      signal_id: SignalId,
      for_network: NetworkId,
    ) -> DispatchResult {
      if matches!(&signal_id, SignalId::Retirement(_)) && LockedInRetirement::<T>::exists() {
        Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
      }

      // Doesn't check the signal exists due to later checking the favor exists
      // While the signal may have been revoked, making this pointless, it's not worth the storage
      // read on every call to check
      // Since revoke will re-tally, this does technically mean a network will become in-favor of a
      // revoked signal. Since revoke won't re-tally for all networks/lock-in, this is also fine

      Self::revoke_favor_internal(ensure_signed(origin)?, signal_id, for_network)
    }

    /// Emit an event standing against the signal.
    ///
    /// If the origin is currently in favor of the signal, their favor will be revoked.
    #[pallet::call_index(4)]
    #[pallet::weight(0)] // TODO
    pub fn stand_against(
      origin: OriginFor<T>,
      signal_id: SignalId,
      for_network: NetworkId,
    ) -> DispatchResult {
      if LockedInRetirement::<T>::exists() {
        Err::<(), _>(Error::<T>::RetirementSignalLockedIn)?;
      }

      let account = ensure_signed(origin)?;
      // If currently in favor, revoke the favor
      if Favors::<T>::contains_key((signal_id, for_network), account) {
        Self::revoke_favor_internal(account, signal_id, for_network)?;
      } else {
        // Check this Signal exists (which would've been implied by Favors for it existing)
        if let SignalId::Retirement(signal_id) = signal_id {
          if RegisteredRetirementSignals::<T>::get(signal_id).is_none() {
            Err::<(), _>(Error::<T>::NonExistentRetirementSignal)?;
          }
        }
      }

      // Emit an event that we're against the signal
      // No actual effects happen besides this
      Self::deposit_event(Event::<T>::AgainstSignal { signal_id, who: account, for_network });
      Ok(())
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(current_number: BlockNumberFor<T>) -> Weight {
      // If this is the block at which a locked-in signal has been set for long enough, panic
      // This will prevent this block from executing and halt the chain
      if let Some((signal, block_number)) = LockedInRetirement::<T>::get() {
        if block_number == current_number {
          panic!(
            "locked-in signal {} has been set for too long",
            sp_core::hexdisplay::HexDisplay::from(&signal),
          );
        }
      }
      Weight::zero() // TODO
    }
  }
}

pub use pallet::*;
