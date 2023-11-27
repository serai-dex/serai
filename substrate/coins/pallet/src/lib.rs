#![cfg_attr(not(feature = "std"), no_std)]

use serai_primitives::{Coin, SubstrateAmount, Balance};

pub trait AllowMint {
  fn allow(balance: &Balance) -> bool;
}

impl AllowMint for () {
  fn allow(_: &Balance) -> bool {
    true
  }
}

#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use sp_std::{vec::Vec, any::TypeId};
  use sp_core::sr25519::Public;
  use sp_runtime::{
    traits::{DispatchInfoOf, PostDispatchInfoOf},
    transaction_validity::{TransactionValidityError, InvalidTransaction},
  };

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use pallet_transaction_payment::{Config as TpConfig, OnChargeTransaction};

  use serai_primitives::*;
  pub use coins_primitives as primitives;
  use primitives::*;

  type LiquidityTokensInstance = crate::Instance1;

  #[pallet::config]
  pub trait Config<I: 'static = ()>: frame_system::Config<AccountId = Public> {
    type RuntimeEvent: From<Event<Self, I>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    type AllowMint: AllowMint;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config<I>, I: 'static = ()> {
    pub accounts: Vec<(T::AccountId, Balance)>,
    pub _ignore: PhantomData<I>,
  }

  impl<T: Config<I>, I: 'static> Default for GenesisConfig<T, I> {
    fn default() -> Self {
      GenesisConfig { accounts: Default::default(), _ignore: Default::default() }
    }
  }

  #[pallet::error]
  pub enum Error<T, I = ()> {
    AmountOverflowed,
    NotEnoughCoins,
    BurnWithInstructionNotAllowed,
    NotEnoughStake,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config<I>, I: 'static = ()> {
    Mint { to: Public, balance: Balance },
    Burn { from: Public, balance: Balance },
    BurnWithInstruction { from: Public, instruction: OutInstructionWithBalance },
    Transfer { from: Public, to: Public, balance: Balance },
  }

  #[pallet::pallet]
  pub struct Pallet<T, I = ()>(_);

  /// The amount of coins each account has.
  // Identity is used as the second key's hasher due to it being a non-manipulatable fixed-space
  // ID.
  #[pallet::storage]
  #[pallet::getter(fn balances)]
  pub type Balances<T: Config<I>, I: 'static = ()> =
    StorageDoubleMap<_, Blake2_128Concat, Public, Identity, Coin, SubstrateAmount, ValueQuery>;

  /// The total supply of each coin.
  // We use Identity type here again due to reasons stated in the Balances Storage.
  #[pallet::storage]
  #[pallet::getter(fn supply)]
  pub type Supply<T: Config<I>, I: 'static = ()> =
    StorageMap<_, Identity, Coin, SubstrateAmount, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config<I>, I: 'static> BuildGenesisConfig for GenesisConfig<T, I> {
    fn build(&self) {
      // initialize the supply of the coins
      // TODO: Don't use COINS yet GenesisConfig so we can safely expand COINS
      for c in &COINS {
        Supply::<T, I>::set(c, 0);
      }

      // initialize the genesis accounts
      for (account, balance) in &self.accounts {
        Pallet::<T, I>::mint(*account, *balance).unwrap();
      }
    }
  }

  #[pallet::hooks]
  impl<T: Config<I>, I: 'static> Hooks<BlockNumberFor<T>> for Pallet<T, I> {
    fn on_initialize(_: BlockNumberFor<T>) -> Weight {
      // burn the fees collected previous block
      let coin = Coin::Serai;
      let amount = Self::balance(FEE_ACCOUNT.into(), coin);
      // we can unwrap, we are not burning more then what we have
      // If this errors, it'll halt the runtime however (due to being called at the start of every
      // block), requiring extra care when reviewing
      Self::burn_internal(FEE_ACCOUNT.into(), Balance { coin, amount }).unwrap();
      Weight::zero() // TODO
    }
  }

  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    /// Returns the balance of a given account for `coin`.
    pub fn balance(of: Public, coin: Coin) -> Amount {
      Amount(Self::balances(of, coin))
    }

    fn decrease_balance_internal(from: Public, balance: Balance) -> Result<(), Error<T, I>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(from, coin)
        .checked_sub(balance.amount.0)
        .ok_or(Error::<T, I>::NotEnoughCoins)?;

      // save
      if new_amount == 0 {
        Balances::<T, I>::remove(from, coin);
      } else {
        Balances::<T, I>::set(from, coin, new_amount);
      }
      Ok(())
    }

    fn increase_balance_internal(to: Public, balance: Balance) -> Result<(), Error<T, I>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(to, coin)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T, I>::AmountOverflowed)?;

      // save
      Balances::<T, I>::set(to, coin, new_amount);
      Ok(())
    }

    /// Mint `balance` to the given account.
    ///
    /// Errors if any amount overflows.
    pub fn mint(to: Public, balance: Balance) -> Result<(), Error<T, I>> {
      let new_supply = Self::supply(balance.coin)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T, I>::AmountOverflowed)?;

      // skip the economics check for lp tokens.
      if TypeId::of::<I>() != TypeId::of::<LiquidityTokensInstance>() &&
        !T::AllowMint::allow(&balance)
      {
        Err(Error::<T, I>::NotEnoughStake)?;
      }
      Supply::<T, I>::set(balance.coin, new_supply);

      // update the balance
      Self::increase_balance_internal(to, balance)?;

      Self::deposit_event(Event::Mint { to, balance });
      Ok(())
    }

    /// Burn `balance` from the specified account.
    fn burn_internal(from: Public, balance: Balance) -> Result<(), Error<T, I>> {
      // don't waste time if amount == 0
      if balance.amount.0 == 0 {
        return Ok(());
      }

      // update the balance
      Self::decrease_balance_internal(from, balance)?;

      // update the supply
      let new_supply = Self::supply(balance.coin).checked_sub(balance.amount.0).unwrap();
      Supply::<T, I>::set(balance.coin, new_supply);

      Ok(())
    }

    /// Transfer `balance` from `from` to `to`.
    pub fn transfer_internal(
      from: Public,
      to: Public,
      balance: Balance,
    ) -> Result<(), Error<T, I>> {
      // update balances of accounts
      Self::decrease_balance_internal(from, balance)?;
      Self::increase_balance_internal(to, balance)?;
      Self::deposit_event(Event::Transfer { from, to, balance });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(origin: OriginFor<T>, to: Public, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::transfer_internal(from, to, balance)?;
      Ok(())
    }

    /// Burn `balance` from the caller.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(origin: OriginFor<T>, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::burn_internal(from, balance)?;
      Self::deposit_event(Event::Burn { from, balance });
      Ok(())
    }

    /// Burn `balance` with `OutInstructionWithBalance` from the caller.
    /// Errors if called for SRI or Instance1 instance of this pallet.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn_with_instruction(
      origin: OriginFor<T>,
      instruction: OutInstructionWithBalance,
    ) -> DispatchResult {
      if instruction.balance.coin == Coin::Serai {
        Err(Error::<T, I>::BurnWithInstructionNotAllowed)?;
      }
      if TypeId::of::<I>() == TypeId::of::<LiquidityTokensInstance>() {
        Err(Error::<T, I>::BurnWithInstructionNotAllowed)?;
      }

      let from = ensure_signed(origin)?;
      Self::burn_internal(from, instruction.balance)?;
      Self::deposit_event(Event::BurnWithInstruction { from, instruction });
      Ok(())
    }
  }

  impl<T: Config> OnChargeTransaction<T> for Pallet<T>
  where
    T: TpConfig,
  {
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
