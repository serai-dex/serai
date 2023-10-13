#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use serai_primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = PublicKey> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::error]
  pub enum Error<T> {
    AmountOverflowed,
    NotEnoughFunds,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Minted { at: T::AccountId, coin: Coin, amount: SubstrateAmount },
    Burnt { at: T::AccountId, coin: Coin, amount: SubstrateAmount },
    Transferred { from: T::AccountId, to: T::AccountId, coin: Coin, amount: SubstrateAmount },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of funds each account has.
  #[pallet::storage]
  #[pallet::getter(fn coins)]
  pub type Coins<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Identity, Coin, SubstrateAmount>;

  impl<T: Config> Pallet<T> {
    /// Returns the balance of a given account for `coin`.
    pub fn balance(of: T::AccountId, coin: Coin) -> SubstrateAmount {
      Self::coins(of, coin).unwrap_or(0)
    }

    /// Mints amount at the given account, errors if amount overflows.
    pub fn mint(at: T::AccountId, coin: Coin, amount: SubstrateAmount) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if amount == 0 {
        return Ok(());
      }

      // add amount to account
      let new_amount = Self::coins(at, coin)
        .unwrap_or(0)
        .checked_add(amount)
        .ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Coins::<T>::set(at, coin, Some(new_amount));

      Self::deposit_event(Event::Minted { at, coin, amount });
      Ok(())
    }

    /// Burns amount at the given account, errors if not enough funds to burn.
    pub fn burn(at: T::AccountId, coin: Coin, amount: SubstrateAmount) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if amount == 0 {
        return Ok(());
      }

      // sub amount from account
      let new_amount =
        Self::coins(at, coin).unwrap_or(0).checked_sub(amount).ok_or(Error::<T>::NotEnoughFunds)?;

      if new_amount == 0 {
        Coins::<T>::remove(at, coin);
      } else {
        Coins::<T>::set(at, coin, Some(new_amount));
      }

      Self::deposit_event(Event::Burnt { at, coin, amount });
      Ok(())
    }

    // TODO: fees are deducted beforehand?
    /// Transfers coins from `from` to `to`.
    fn transfer_internal(
      from: T::AccountId,
      to: T::AccountId,
      coin: Coin,
      amount: SubstrateAmount,
    ) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if amount == 0 {
        return Ok(());
      }

      // sub the amount from "from"
      let from_amount = Self::coins(from, coin)
        .unwrap_or(0)
        .checked_sub(amount)
        .ok_or(Error::<T>::NotEnoughFunds)?;

      // add to "to"
      let to_amount = Self::coins(to, coin)
        .unwrap_or(0)
        .checked_add(amount)
        .ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Coins::<T>::set(to, coin, Some(to_amount));
      if from_amount == 0 {
        Coins::<T>::remove(from, coin);
      } else {
        Coins::<T>::set(from, coin, Some(from_amount));
      }

      Self::deposit_event(Event::Transferred { from, to, coin, amount });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(
      o: OriginFor<T>,
      to: SeraiAddress,
      coin: Coin,
      amount: SubstrateAmount,
    ) -> DispatchResult {
      let from = ensure_signed(o)?;
      Self::transfer_internal(from, to.into(), coin, amount)?;
      Ok(())
    }
  }
}

pub use pallet::*;
