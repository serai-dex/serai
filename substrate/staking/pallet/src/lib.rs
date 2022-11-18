#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_runtime::traits::TrailingZeroInput;

  use frame_system::pallet_prelude::*;
  use frame_support::{
    pallet_prelude::*,
    traits::{Currency, tokens::ExistenceRequirement},
  };

  use staking_primitives::AllocatedStaking;

  #[pallet::error]
  pub enum Error<T> {
    BondUnavailable,
    InsufficientDelegation,
  }

  // TODO: Event

  #[pallet::config]
  pub trait Config: frame_system::Config {
    type Currency: Currency<Self::AccountId, Balance = u64>;
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  // There's an argument some of the following should be in AccountData
  // AccountData is also premised on enabling reaping, when reaping is more of a pain than a gain

  /// The amount of funds this account has staked.
  #[pallet::storage]
  #[pallet::getter(fn staked)]
  pub type Staked<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

  /// The amount of funds a staking account has delegated to another.
  #[pallet::storage]
  #[pallet::getter(fn delegated)]
  pub type Delegations<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    T::AccountId,
    Blake2_128Concat,
    T::AccountId,
    u64,
    ValueQuery,
  >;

  /// The amount of bond this account has been delegated.
  #[pallet::storage]
  #[pallet::getter(fn bond)]
  pub type Bond<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

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

    fn add_delegation(from: &T::AccountId, to: &T::AccountId, amount: u64) {
      Delegations::<T>::mutate(from, to, |delegated| *delegated += amount);
      Bond::<T>::mutate(to, |bond| *bond += amount);
    }

    fn remove_delegation(from: &T::AccountId, to: &T::AccountId, amount: u64) -> DispatchResult {
      // This was cleaner when it was the if statements, then mutation, which also followed the
      // checks, effects, interactions pattern
      // Doing so resulted in two DB lookups however, which was inefficient, and interactions
      // before all checks are fine
      // They used to not be, and require `transactional` to achieve that behavior, yet that's
      // been deprecated for it to be the default behavior
      Bond::<T>::try_mutate(to, |bond| {
        let available = *bond - Self::allocated(to);
        if available < amount {
          Err(Error::<T>::BondUnavailable)?;
        }
        *bond -= amount;
        Ok::<_, DispatchError>(())
      })?;

      Delegations::<T>::try_mutate(from, to, |delegated| {
        if *delegated < amount {
          Err(Error::<T>::InsufficientDelegation)?;
        }
        *delegated -= amount;
        Ok(())
      })
    }

    fn add_stake(account: &T::AccountId, delegate: &T::AccountId, amount: u64) {
      Staked::<T>::mutate(account, |staked| *staked += amount);
      Self::add_delegation(account, delegate, amount);
    }

    fn remove_stake(
      account: &T::AccountId,
      delegate: &T::AccountId,
      amount: u64,
    ) -> DispatchResult {
      Self::remove_delegation(account, delegate, amount)?;
      Staked::<T>::mutate(account, |staked| {
        // Check this invariant in the name of safety
        if *staked < amount {
          panic!("delegations exceeded staked funds");
        }
        *staked -= amount;
      });
      Ok(())
    }

    fn move_delegation(
      account: &T::AccountId,
      from: &T::AccountId,
      to: &T::AccountId,
      amount: u64,
    ) -> DispatchResult {
      Self::remove_delegation(account, from, amount)?;
      Self::add_delegation(account, to, amount);
      Ok(())
    }

    fn allocate_internal(account: &T::AccountId, amount: u64) -> Result<(), Error<T>> {
      Allocated::<T>::try_mutate(account, |allocated| {
        let available = Self::bond(account) - *allocated;
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
          panic!("deallocating more than allocated");
        }
        *allocated -= amount;
        Ok(())
      })
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Stake funds from this account, delegating them to the specified account.
    #[pallet::weight(0)] // TODO
    pub fn stake(
      origin: OriginFor<T>,
      delegate: T::AccountId,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      // Serai accounts are solely public keys. Accordingly, there's no harm to letting accounts
      // die. They'll simply be re-instantiated later
      // AllowDeath accordingly to not add additional requirements (and therefore annoyances)
      T::Currency::transfer(&signer, &Self::account(), amount, ExistenceRequirement::AllowDeath)?;
      Self::add_stake(&signer, &delegate, amount);
      Ok(())
    }

    /// Undelegate funds from one account, re-delegating to another. Only unallocated funds may be
    /// redelegated.
    #[pallet::weight(0)] // TODO
    pub fn redelegate(
      origin: OriginFor<T>,
      from: T::AccountId,
      to: T::AccountId,
      amount: u64,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      Self::move_delegation(&signer, &from, &to, amount)?;
      Ok(())
    }

    /// Unstake funds currently delegated to the specified account. Only unallocated funds may be
    /// unstaked.
    #[pallet::weight(0)] // TODO
    pub fn unstake(
      origin: OriginFor<T>,
      delegate: T::AccountId,
      #[pallet::compact] amount: u64,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      Self::remove_stake(&signer, &delegate, amount)?;
      // This should never be out of funds as there should always be stakers. Accordingly...
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
