#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_runtime::{traits::TrailingZeroInput, DispatchError};
  use sp_std::vec::Vec;

  use frame_system::pallet_prelude::*;
  use frame_support::{
    pallet_prelude::*,
    traits::{Currency, tokens::ExistenceRequirement},
  };

  use serai_primitives::{NetworkId, Amount, PublicKey};

  use validator_sets_pallet::{Config as VsConfig, Pallet as VsPallet};
  use pallet_session::{Config as SessionConfig, SessionManager};

  #[pallet::error]
  pub enum Error<T> {
    StakeUnavilable,
  }

  // TODO: Event

  #[pallet::config]
  pub trait Config:
    frame_system::Config + VsConfig + SessionConfig<ValidatorId = PublicKey>
  {
    type Currency: Currency<Self::AccountId, Balance = u64>;
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of funds this account has staked.
  #[pallet::storage]
  #[pallet::getter(fn staked)]
  pub type Staked<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

  /// The amount of stake this account has allocated to validator sets.
  #[pallet::storage]
  #[pallet::getter(fn allocated)]
  pub type Allocated<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

  impl<T: Config> Pallet<T> {
    fn account() -> T::AccountId {
      // Substrate has a pattern of using simply using 8-bytes (as a PalletId) directly as an
      // AccountId. This replicates its internals to remove the 8-byte limit
      T::AccountId::decode(&mut TrailingZeroInput::new(b"staking")).unwrap()
    }

    fn add_stake(account: &T::AccountId, amount: u64) {
      Staked::<T>::mutate(account, |staked| *staked += amount);
    }

    fn remove_stake(account: &T::AccountId, amount: u64) -> DispatchResult {
      Staked::<T>::mutate(account, |staked| {
        let available = *staked - Self::allocated(account);
        if available < amount {
          Err(Error::<T>::StakeUnavilable)?;
        }
        *staked -= amount;
        Ok::<_, DispatchError>(())
      })
    }

    fn allocate_internal(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Allocated::<T>::try_mutate(account, |allocated| {
        let available = Self::staked(account) - *allocated;
        if available < amount {
          Err(Error::<T>::StakeUnavilable)?;
        }
        *allocated += amount;
        Ok(())
      })
    }

    #[allow(unused)] // TODO
    fn deallocate_internal(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Allocated::<T>::try_mutate(account, |allocated| {
        if *allocated < amount {
          Err(Error::<T>::StakeUnavilable)?;
        }
        *allocated -= amount;
        Ok(())
      })
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Stake funds from this account.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn stake(origin: OriginFor<T>, #[pallet::compact] amount: u64) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      // Serai accounts are solely public keys. Accordingly, there's no harm to letting accounts
      // die. They'll simply be re-instantiated later
      // AllowDeath accordingly to not add additional requirements (and therefore annoyances)
      T::Currency::transfer(&signer, &Self::account(), amount, ExistenceRequirement::AllowDeath)?;
      Self::add_stake(&signer, amount);
      Ok(())
    }

    /// Unstake funds from this account. Only unallocated funds may be unstaked.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn unstake(origin: OriginFor<T>, #[pallet::compact] amount: u64) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      Self::remove_stake(&signer, amount)?;
      // This should never be out of funds as there should always be stakers. Accordingly...
      T::Currency::transfer(&Self::account(), &signer, amount, ExistenceRequirement::KeepAlive)?;
      Ok(())
    }

    /// Allocate `amount` to a given validator set.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn allocate(
      origin: OriginFor<T>,
      network: NetworkId,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let account = ensure_signed(origin)?;

      // add to amount allocated
      Self::allocate_internal(&account, amount)?;

      // increase allocation for participant in validator set
      VsPallet::<T>::increase_allocation(network, account, Amount(amount))
    }

    /// Deallocate `amount` from a given validator set.
    #[pallet::call_index(3)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn deallocate(
      origin: OriginFor<T>,
      network: NetworkId,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let account = ensure_signed(origin)?;

      // decrease allocation in validator set
      VsPallet::<T>::decrease_allocation(network, account, Amount(amount))?;

      // We don't immediately call deallocate since the deallocation only takes effect in the next
      // session
      // TODO: If this validator isn't active, allow immediate deallocation
      Ok(())
    }

    // TODO: Add a function to reclaim deallocated funds
  }

  // Call order is end_session(i - 1) -> start_session(i) -> new_session(i + 1)
  // new_session(i + 1) is called immediately after start_session(i)
  // then we wait until the session ends then get a call to end_session(i) and so on.
  impl<T: Config> SessionManager<T::ValidatorId> for Pallet<T> {
    fn new_session(_new_index: u32) -> Option<Vec<T::ValidatorId>> {
      // Don't call new_session multiple times on genesis
      // TODO: Will this cause pallet_session::Pallet::current_index to desync from validator-sets?
      if frame_system::Pallet::<T>::block_number() > 1u32.into() {
        VsPallet::<T>::new_session();
      }
      // TODO: Where do we return their stake?
      Some(VsPallet::<T>::validators(NetworkId::Serai))
    }

    fn new_session_genesis(_: u32) -> Option<Vec<T::ValidatorId>> {
      Some(VsPallet::<T>::validators(NetworkId::Serai))
    }

    fn end_session(_end_index: u32) {}

    fn start_session(_start_index: u32) {}
  }
}

pub use pallet::*;
