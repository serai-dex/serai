#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_std::vec::Vec;
  use sp_core::sr25519::Public;
  use sp_runtime::{
    traits::{DispatchInfoOf, PostDispatchInfoOf},
    transaction_validity::{TransactionValidityError, InvalidTransaction},
  };

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use pallet_transaction_payment::{Config as TpConfig, OnChargeTransaction};

  use dex_pallet::{Currency, Assets, Config as DexConfig};

  use serai_primitives::*;
  pub use coins_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = Public> + TpConfig + DexConfig<Balance = SubstrateAmount, AssetId = Coin> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    pub accounts: Vec<(T::AccountId, Balance)>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { accounts: Default::default() }
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    AmountOverflowed,
    NotEnoughCoins,
    SriBurnNotAllowed,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Mint { to: Public, balance: Balance },
    Burn { from: Public, instruction: OutInstructionWithBalance },
    SriBurn { from: Public, amount: Amount },
    Transfer { from: Public, to: Public, balance: Balance },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of coins each account has.
  // Identity is used as the second key's hasher due to it being a non-manipulatable fixed-space
  // ID.
  #[pallet::storage]
  #[pallet::getter(fn balances)]
  pub type Balances<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, Public, Identity, Coin, SubstrateAmount, ValueQuery>;

  /// The total supply of each coin.
  // We use Identity type here again due to reasons stated in the Balances Storage.
  #[pallet::storage]
  #[pallet::getter(fn supply)]
  pub type Supply<T: Config> = StorageMap<_, Identity, Coin, SubstrateAmount, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      // initialize the supply of the coins
      for c in COINS.iter() {
        Supply::<T>::set(c, 0);
      }

      // initialize the genesis accounts
      for (account, balance) in self.accounts.iter() {
        Pallet::<T>::mint(*account, *balance).unwrap();
      }
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(_: BlockNumberFor<T>) -> Weight {
      // burn the fees collected previous block
      let coin = Coin::Serai;
      let amount = Self::balance(FEE_ACCOUNT.into(), coin);
      // we can unwrap, we are not burning more then what we have
      // If this errors, it'll halt the runtime however (due to being called at the start of every
      // block), requiring extra care when reviewing
      Self::burn_sri(FEE_ACCOUNT.into(), amount).unwrap();
      Weight::zero() // TODO
    }
  }

  impl<T: Config> Pallet<T> {
    /// Returns the balance of a given account for `coin`.
    pub fn balance(of: Public, coin: Coin) -> Amount {
      Amount(Self::balances(of, coin))
    }

    fn decrease_balance_internal(from: Public, balance: Balance) -> Result<(), Error<T>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(from, coin)
        .checked_sub(balance.amount.0)
        .ok_or(Error::<T>::NotEnoughCoins)?;

      // save
      if new_amount == 0 {
        Balances::<T>::remove(from, coin);
      } else {
        Balances::<T>::set(from, coin, new_amount);
      }
      Ok(())
    }

    fn increase_balance_internal(to: Public, balance: Balance) -> Result<(), Error<T>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(to, coin)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Balances::<T>::set(to, coin, new_amount);
      Ok(())
    }

    /// Mint `balance` to the given account.
    ///
    /// Errors if any amount overflows.
    pub fn mint(to: Public, balance: Balance) -> Result<(), Error<T>> {
      // update the balance
      Self::increase_balance_internal(to, balance)?;

      // update the supply
      let new_supply = Self::supply(balance.coin)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(balance.coin, new_supply);

      Self::deposit_event(Event::Mint { to, balance });
      Ok(())
    }

    // Burn `balance` from the specified account.
    fn burn_internal(from: Public, balance: Balance) -> Result<(), Error<T>> {
      // don't waste time if amount == 0
      if balance.amount.0 == 0 {
        return Ok(());
      }

      // update the balance
      Self::decrease_balance_internal(from, balance)?;

      // update the supply
      let new_supply = Self::supply(balance.coin).checked_sub(balance.amount.0).unwrap();
      Supply::<T>::set(balance.coin, new_supply);

      Ok(())
    }

    pub fn burn_sri(from: Public, amount: Amount) -> Result<(), Error<T>> {
      Self::burn_internal(from, Balance { coin: Coin::Serai, amount })?;
      Self::deposit_event(Event::SriBurn { from, amount });
      Ok(())
    }

    pub fn burn_non_sri(
      from: Public,
      instruction: OutInstructionWithBalance,
    ) -> Result<(), Error<T>> {
      if instruction.balance.coin == Coin::Serai {
        Err(Error::<T>::SriBurnNotAllowed)?;
      }
      Self::burn_internal(from, instruction.balance)?;
      Self::deposit_event(Event::Burn { from, instruction });
      Ok(())
    }

    /// Transfer `balance` from `from` to `to`.
    pub fn transfer_internal(from: Public, to: Public, balance: Balance) -> Result<(), Error<T>> {
      // update balances of accounts
      Self::decrease_balance_internal(from, balance)?;
      Self::increase_balance_internal(to, balance)?;
      Self::deposit_event(Event::Transfer { from, to, balance });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(origin: OriginFor<T>, to: Public, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::transfer_internal(from, to, balance)?;
      Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(origin: OriginFor<T>, instruction: OutInstructionWithBalance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::burn_non_sri(from, instruction)?;
      Ok(())
    }
  }

  impl<T: Config> Currency<T::AccountId> for Pallet<T> {
    type Balance = T::Balance;

    fn balance(of: &Public) -> Self::Balance {
      Self::balance(*of, Coin::Serai).0
    }

    /// TODO: make sure of coin precision here.
    fn minimum_balance() -> Self::Balance {
      1
    }

    fn transfer(from: &Public, to: &Public, amount: Self::Balance) -> Result<Self::Balance, DispatchError> {
      let balance = Balance { coin: Coin::Serai, amount: Amount(amount) };
      Self::transfer_internal(*from, *to, balance)?;
      Ok(amount)
    }
  }

  impl<T: Config> Assets<T::AccountId> for Pallet<T> {
    type Balance = T::Balance;
    type AssetId = T::AssetId;

    fn balance(coin: Self::AssetId, of: &Public) -> Self::Balance {
      Self::balance(*of, coin).0
    }

    fn minimum_balance(_: Self::AssetId) -> Self::Balance {
      1
    }

    fn transfer(coin: Self::AssetId, from: &Public, to: &Public, amount: Self::Balance) -> Result<Self::Balance, DispatchError> {
      let balance = Balance { coin, amount: Amount(amount) };
      Self::transfer_internal(*from, *to, balance)?;
      Ok(amount)
    }
  }

  impl<T: Config> OnChargeTransaction<T> for Pallet<T> {
    type Balance = SubstrateAmount;
    type LiquidityInfo = Option<SubstrateAmount>;

    fn withdraw_fee(
      who: &Public,
      _call: &T::RuntimeCall,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      fee: Self::Balance,
      _tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
      if fee == 0 {
        return Ok(None);
      }

      let balance = Balance { coin: Coin::Serai, amount: Amount(fee) };
      match Self::transfer_internal(*who, FEE_ACCOUNT.into(), balance) {
        Err(_) => Err(InvalidTransaction::Payment)?,
        Ok(()) => Ok(Some(fee)),
      }
    }

    fn correct_and_deposit_fee(
      who: &Public,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      _post_info: &PostDispatchInfoOf<T::RuntimeCall>,
      corrected_fee: Self::Balance,
      _tip: Self::Balance,
      already_withdrawn: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
      if let Some(paid) = already_withdrawn {
        let refund_amount = paid.saturating_sub(corrected_fee);
        let balance = Balance { coin: Coin::Serai, amount: Amount(refund_amount) };
        Self::transfer_internal(FEE_ACCOUNT.into(), *who, balance)
          .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
      }
      Ok(())
    }
  }
}

pub use pallet::*;
