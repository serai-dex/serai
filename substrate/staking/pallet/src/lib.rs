#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_runtime::{traits::TrailingZeroInput, DispatchError};

  use frame_system::pallet_prelude::*;
  use frame_support::{
    pallet_prelude::*,
    traits::{Currency, tokens::ExistenceRequirement},
  };

  use staking_primitives::AllocatedStaking;

  #[pallet::error]
  pub enum Error<T> {
    BondUnavailable,
    InSufficientAllocation,
  }

  // TODO: Event

  #[pallet::config]
  pub trait Config: frame_system::Config {
    type Currency: Currency<Self::AccountId, Balance = u64>;
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  // There's an argument some of the following should be in AccountData
  // AccountData is also premised on enabling reaping, when reaping is more of a pain than a gain

  /// The amount of funds this account has staked.
  #[pallet::storage]
  #[pallet::getter(fn staked)]
  pub type Staked<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

  /// The amount of bond this account has allocated to validator sets.
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

    fn remove_stake(
      account: &T::AccountId,
      amount: u64,
    ) -> DispatchResult {
      Staked::<T>::mutate(account, |staked| {
        let available = *staked - Self::allocated(account);
        // Check this invariant in the name of safety
        if available < amount {
          Err(Error::<T>::BondUnavailable)?;
        }
        *staked -= amount;
        Ok::<_, DispatchError>(())
      })
    }

    fn allocate_internal(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Allocated::<T>::try_mutate(account, |allocated| {
        let available = Self::staked(account) - *allocated;
        if available < amount {
          Err(Error::<T>::BondUnavailable)?;
        }
        *allocated += amount;
        Ok(())
      })
    }

    fn deallocate_internal(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Allocated::<T>::try_mutate(account, |allocated| {
        if *allocated < amount {
          Err(Error::<T>::InSufficientAllocation)?;
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
    pub fn stake(
      origin: OriginFor<T>,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      // Serai accounts are solely public keys. Accordingly, there's no harm to letting accounts
      // die. They'll simply be re-instantiated later
      // AllowDeath accordingly to not add additional requirements (and therefore annoyances)
      T::Currency::transfer(&signer, &Self::account(), amount, ExistenceRequirement::AllowDeath)?;
      Self::add_stake(&signer, amount);
      Ok(())
    }

    /// Unstake funds from this account. Only unallocated funds may be
    /// unstaked.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn unstake(
      origin: OriginFor<T>,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      Self::remove_stake(&signer, amount)?;
      // This should never be out of funds as there should always be stakers. Accordingly...
      // TODO: What if this fails for some reason but we removed the stake above?
      T::Currency::transfer(&Self::account(), &signer, amount, ExistenceRequirement::KeepAlive)?;
      Ok(())
    }
  }

  impl<T: Config> AllocatedStaking<T> for Pallet<T> {
    type Error = Error<T>;

    fn allocate(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Self::allocate_internal(account, amount)
    }
    fn deallocate(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Self::deallocate_internal(account, amount)
    }
  }
}

pub use pallet::*;
