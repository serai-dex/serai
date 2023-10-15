#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::{*, ValueQuery, OptionQuery};
  use frame_system::pallet_prelude::*;

  use sp_runtime::{
    traits::{DispatchInfoOf, PostDispatchInfoOf},
    transaction_validity::{TransactionValidityError, InvalidTransaction},
  };
  use sp_std::vec::Vec;

  use pallet_transaction_payment::{Config as TpConfig, OnChargeTransaction};

  use serai_primitives::*;
  use coins_primitives::OutInstruction;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = PublicKey> + TpConfig {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    pub accounts: Vec<(T::AccountId, Coin, SubstrateAmount)>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { accounts: Default::default() }
    }
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
    Burnt { at: T::AccountId, coin: Coin, amount: SubstrateAmount, instruction: OutInstruction },
    Transferred { from: T::AccountId, to: T::AccountId, coin: Coin, amount: SubstrateAmount },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of funds each account has.
  #[pallet::storage]
  #[pallet::getter(fn coins)]
  pub type Coins<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    T::AccountId,
    Identity,
    Coin,
    SubstrateAmount,
    OptionQuery,
  >;

  /// The total supply of each coin.
  #[pallet::storage]
  #[pallet::getter(fn supply)]
  pub type Supply<T: Config> = StorageMap<_, Blake2_128Concat, Coin, SubstrateAmount, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      // initialize the supply of the coins
      for c in COINS.iter() {
        Supply::<T>::set(c, 0);
      }

      // initialize the genesis accounts
      for (account, coin, amount) in self.accounts.iter() {
        Coins::<T>::set(account, coin, Some(*amount));
        let current_supply = Supply::<T>::get(coin);
        Supply::<T>::set(coin, current_supply.checked_add(*amount).unwrap());
      }
    }
  }

  impl<T: Config> Pallet<T> {
    /// Returns the balance of a given account for `coin`.
    pub fn balance(of: &T::AccountId, coin: Coin) -> SubstrateAmount {
      Self::coins(of, coin).unwrap_or(0)
    }

    fn increase_supply(coin: Coin, by: SubstrateAmount) -> Result<(), Error<T>> {
      // update the supply
      let new_supply = Self::supply(coin).checked_add(by).ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(coin, new_supply);
      Ok(())
    }

    fn decrease_supply(coin: Coin, by: SubstrateAmount) -> Result<(), Error<T>> {
      // update the supply
      let new_supply = Self::supply(coin).checked_sub(by).ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(coin, new_supply);
      Ok(())
    }

    /// Mints amount at the given account, errors if amount overflows.
    pub fn mint(at: &T::AccountId, coin: Coin, amount: SubstrateAmount) -> Result<(), Error<T>> {
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
      Self::increase_supply(coin, amount)?;

      Self::deposit_event(Event::Minted { at: *at, coin, amount });
      Ok(())
    }

    /// Burns amount at the given account, errors if not enough funds to burn.
    pub fn burn_internal(
      at: &T::AccountId,
      coin: Coin,
      amount: SubstrateAmount,
      instruction: OutInstruction,
    ) -> Result<(), Error<T>> {
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

      // something should have gone horribly wrong if we error on this.
      if Self::decrease_supply(coin, amount).is_err() {
        panic!("we tried to burn more assets than what we have");
      }

      Self::deposit_event(Event::Burnt { at: *at, coin, amount, instruction });
      Ok(())
    }

    /// Transfers coins from `from` to `to`.
    pub fn transfer_internal(
      from: &T::AccountId,
      to: &T::AccountId,
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

      // TODO: update the supply if fees are really being burned or do that
      // within the fee code.

      Self::deposit_event(Event::Transferred { from: *from, to: *to, coin, amount });
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
      Self::transfer_internal(&from, &to.into(), coin, amount)?;
      Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(o: OriginFor<T>, balance: Balance, instruction: OutInstruction) -> DispatchResult {
      let at = ensure_signed(o)?;
      Self::burn_internal(&at, balance.coin, balance.amount.0, instruction)?;
      Ok(())
    }
  }

  #[derive(Default)]
  pub struct Imbalance {
    pub amount: u64,
  }

  impl<T: Config> OnChargeTransaction<T> for Pallet<T> {
    type Balance = SubstrateAmount;
    type LiquidityInfo = Option<Imbalance>;

    /// Before the transaction is executed the payment of the transaction fees
    /// need to be secured.
    ///
    /// Note: The `fee` already includes the `tip`.
    fn withdraw_fee(
      who: &T::AccountId,
      _call: &T::RuntimeCall,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      fee: Self::Balance,
      _tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
      // TODO: Could we have a 0 fee tx? Error in this case?
      if fee == 0 {
        return Ok(None);
      }

      // TODO: Where should the fees go? O_o.
      let dummy = [0u8; 32];
      let out = OutInstruction::decode(&mut dummy.as_slice()).unwrap();
      match Self::burn_internal(who, Coin::Serai, fee, out) {
        Err(_) => Err(InvalidTransaction::Payment.into()),
        Ok(()) => Ok(Some(Imbalance { amount: fee })),
      }
    }

    /// After the transaction was executed the actual fee can be calculated.
    /// This function should refund any overpaid fees and optionally deposit
    /// the corrected amount.
    ///
    /// Note: The `fee` already includes the `tip`.
    fn correct_and_deposit_fee(
      who: &T::AccountId,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      _post_info: &PostDispatchInfoOf<T::RuntimeCall>,
      corrected_fee: Self::Balance,
      _tip: Self::Balance,
      already_withdrawn: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
      if let Some(paid) = already_withdrawn {
        let refund_amount = paid.amount.saturating_sub(corrected_fee);
        Self::mint(who, Coin::Serai, refund_amount)
          .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
      }
      Ok(())
    }
  }
}

pub use pallet::*;
