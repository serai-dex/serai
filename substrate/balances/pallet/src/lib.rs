#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use serai_primitives::{*, SeraiAddress, SubstrateAmount};

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
    Minted { at: T::AccountId, amount: SubstrateAmount },
    Transferred { from: T::AccountId, to: T::AccountId, amount: SubstrateAmount },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of funds each account has.
  #[pallet::storage]
  #[pallet::getter(fn balances)]
  pub type Balances<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, SubstrateAmount, OptionQuery>;

  impl<T: Config> Pallet<T> {
    pub fn mint(at: T::AccountId, amount: SubstrateAmount) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if amount == 0 {
        return Ok(());
      }

      // add amount to account
      let to_amount =
        Self::balances(at).unwrap_or(0).checked_add(amount).ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Balances::<T>::set(at, Some(to_amount));

      Self::deposit_event(Event::Minted { at, amount });
      Ok(())
    }

    // TODO: fees are deducted beforehand?
    fn transfer_internal(
      from: T::AccountId,
      to: T::AccountId,
      amount: SubstrateAmount,
    ) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if amount == 0 {
        return Ok(());
      }

      // sub the amount from "from"
      // TODO: implement Default 0 for substrate amount instead of doing unwrap_or each time?
      let from_amount =
        Self::balances(from).unwrap_or(0).checked_sub(amount).ok_or(Error::<T>::NotEnoughFunds)?;

      // add to "to"
      let to_amount =
        Self::balances(to).unwrap_or(0).checked_add(amount).ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Balances::<T>::set(to, Some(to_amount));
      if from_amount == 0 {
        Balances::<T>::remove(from);
      } else {
        Balances::<T>::set(from, Some(from_amount));
      }

      Self::deposit_event(Event::Transferred { from, to, amount });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(o: OriginFor<T>, to: SeraiAddress, amount: SubstrateAmount) -> DispatchResult {
      let from = ensure_signed(o)?;
      Self::transfer_internal(from, to.into(), amount)?;
      Ok(())
    }
  }
}

pub use pallet::*;
