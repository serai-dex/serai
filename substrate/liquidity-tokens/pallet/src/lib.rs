#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_core::sr25519::Public;
  use sp_std::vec::Vec;
  use frame_support::pallet_prelude::*;

  use dex_primitives::LiquidityTokens;
  use serai_primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = Public> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::error]
  pub enum Error<T> {
    AmountOverflowed,
    NotEnoughCoins,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    LtMint { to: Public, token: u32, amount: Amount },
    LtBurn { from: Public, token: u32, amount: Amount },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of coins each account has.
  // Identity is used as the second key's hasher due to it being a non-manipulatable fixed-space
  // ID.
  #[pallet::storage]
  #[pallet::getter(fn balances)]
  pub type Balances<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    Public,
    Blake2_128Concat,
    u32,
    SubstrateAmount,
    OptionQuery,
  >;

  /// The total supply of each coin.
  // We use Identity type here again due to reasons stated in the Balances Storage.
  #[pallet::storage]
  #[pallet::getter(fn supply)]
  pub type Supply<T: Config> = StorageMap<_, Blake2_128Concat, u32, SubstrateAmount, ValueQuery>;

  // TODO: apis: supply, mint, burn, transfer
  impl<T: Config> Pallet<T> {
    /// Returns the balance of a given account for `token`.
    pub fn balance(token: u32, of: T::AccountId) -> SubstrateAmount {
      Self::balances(of, token).unwrap_or(0)
    }

    /// Mint `balance` to the given account.
    ///
    /// Errors if any amount overflows.
    pub fn mint_into(token: u32, to: Public, amount: SubstrateAmount) -> Result<(), Error<T>> {
      let balance = Self::balances(to, token).unwrap_or(0);

      // update the balance
      let new_amount = balance.checked_add(amount).ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Balances::<T>::set(to, token, Some(new_amount));

      // update the supply
      let new_supply =
        Self::supply(token).checked_add(amount).ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(token, new_supply);

      Self::deposit_event(Event::LtMint { to, token, amount: Amount(amount) });
      Ok(())
    }

    // Burn `balance` from the specified account.
    pub fn burn_from(token: u32, from: Public, amount: SubstrateAmount) -> Result<(), Error<T>> {
      let balance = Self::balances(from, token);
      if balance.is_none() {
        Err(Error::<T>::NotEnoughCoins)?;
      }

      // update the balance
      let new_amount = balance.unwrap().checked_sub(amount).ok_or(Error::<T>::NotEnoughCoins)?;

      // save
      if new_amount == 0 {
        Balances::<T>::remove(from, token);
      } else {
        Balances::<T>::set(from, token, Some(new_amount));
      }

      // update the supply
      let new_supply = Self::supply(token).checked_sub(amount).unwrap();
      if new_supply == 0 {
        Supply::<T>::remove(token);
      } else {
        Supply::<T>::set(token, new_supply);
      }

      Self::deposit_event(Event::LtBurn { from, token, amount: Amount(amount) });
      Ok(())
    }

    pub fn total_issuance(token: u32) -> SubstrateAmount {
      Supply::<T>::get(token)
    }
  }

  impl<T: Config> LiquidityTokens<T::AccountId> for Pallet<T> {
    type Balance = SubstrateAmount;
    type AssetId = u32;

    fn mint_into(
      token: Self::AssetId,
      to: &Public,
      amount: Self::Balance,
    ) -> Result<Self::Balance, DispatchError> {
      Self::mint_into(token, *to, amount)?;
      Ok(amount)
    }

    fn burn_from(
      token: Self::AssetId,
      from: &Public,
      amount: Self::Balance,
    ) -> Result<Self::Balance, DispatchError> {
      Self::burn_from(token, *from, amount)?;
      Ok(amount)
    }

    fn total_issuance(token: Self::AssetId) -> Self::Balance {
      Self::total_issuance(token)
    }

    fn asset_ids() -> Vec<Self::AssetId> {
      Supply::<T>::iter_keys().collect::<Vec<Self::AssetId>>()
    }

    fn balance(token: Self::AssetId, of: &Public) -> Self::Balance {
      Self::balance(token, *of)
    }
  }
}

pub use pallet::*;
