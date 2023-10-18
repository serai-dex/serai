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
  pub use coins_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = PublicKey> + TpConfig {
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
    Mint { address: SeraiAddress, balance: Balance },
    Burn { address: SeraiAddress, instruction: OutInstructionWithBalance },
    SriBurn { address: SeraiAddress, amount: Amount },
    Transfer { from: SeraiAddress, to: SeraiAddress, balance: Balance },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The amount of coins each account has.
  // We use Identity type for the second key due to it being a non-manipulatable fixed-space ID.
  #[pallet::storage]
  #[pallet::getter(fn balances)]
  pub type Balances<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    T::AccountId,
    Identity,
    Coin,
    SubstrateAmount,
    OptionQuery,
  >;

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
        Pallet::<T>::mint(account, *balance).unwrap();
      }
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(_: BlockNumberFor<T>) -> Weight {
      // burn the fees collected previous block
      let coin = Coin::Serai;
      let amount = Self::balance(&FEE_ACCOUNT.into(), coin);
      // we can unwrap, we are not burning more then what we have.
      Self::burn_internal(&FEE_ACCOUNT.into(), Balance { coin, amount }, None).unwrap();
      Weight::zero() // TODO
    }
  }

  impl<T: Config> Pallet<T> {
    /// Returns the balance of a given account for `coin`.
    pub fn balance(of: &T::AccountId, coin: Coin) -> Amount {
      Amount(Self::balances(of, coin).unwrap_or(0))
    }

    fn decrease_balance_internal(at: &T::AccountId, balance: Balance) -> Result<(), Error<T>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(at, coin)
        .unwrap_or(0)
        .checked_sub(balance.amount.0)
        .ok_or(Error::<T>::NotEnoughCoins)?;

      // save
      if new_amount == 0 {
        Balances::<T>::remove(at, coin);
      } else {
        Balances::<T>::set(at, coin, Some(new_amount));
      }
      Ok(())
    }

    fn increase_balance_internal(at: &T::AccountId, balance: Balance) -> Result<(), Error<T>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount = Self::balances(at, coin)
        .unwrap_or(0)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T>::AmountOverflowed)?;

      // save
      Balances::<T>::set(at, coin, Some(new_amount));
      Ok(())
    }

    /// Mints amount at the given account, errors if amount overflows.
    pub fn mint(at: &T::AccountId, balance: Balance) -> Result<(), Error<T>> {
      // update the balance
      Self::increase_balance_internal(at, balance)?;

      // update the supply
      let new_supply = Self::supply(balance.coin)
        .checked_add(balance.amount.0)
        .ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(balance.coin, new_supply);

      Self::deposit_event(Event::Mint { address: SeraiAddress(at.0), balance });
      Ok(())
    }

    /// Burns amount at the given account, errors if not enough funds to burn.
    pub fn burn_internal(
      at: &T::AccountId,
      balance: Balance,
      instruction: Option<OutInstruction>,
    ) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if balance.amount.0 == 0 {
        return Ok(());
      }

      // update the balance
      Self::decrease_balance_internal(at, balance)?;

      // update the supply
      let new_supply = Self::supply(balance.coin)
        .checked_sub(balance.amount.0)
        .ok_or(Error::<T>::AmountOverflowed)?;
      Supply::<T>::set(balance.coin, new_supply);

      if balance.coin == Coin::Serai {
        Self::deposit_event(Event::SriBurn { address: SeraiAddress(at.0), amount: balance.amount });
      } else {
        let out_instruction =
          OutInstructionWithBalance { instruction: instruction.unwrap(), balance };
        Self::deposit_event(Event::Burn {
          address: SeraiAddress(at.0),
          instruction: out_instruction,
        });
      }
      Ok(())
    }

    /// Transfers coins from `from` to `to`.
    pub fn transfer_internal(
      from: &T::AccountId,
      to: &T::AccountId,
      balance: Balance,
    ) -> Result<(), Error<T>> {
      // don't waste time if amount 0.
      if balance.amount.0 == 0 {
        return Ok(());
      }

      // update balances of accounts
      Self::decrease_balance_internal(from, balance)?;
      Self::increase_balance_internal(to, balance)?;

      Self::deposit_event(Event::Transfer {
        from: SeraiAddress(from.0),
        to: SeraiAddress(to.0),
        balance,
      });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(origin: OriginFor<T>, to: SeraiAddress, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::transfer_internal(&from, &to.into(), balance)?;
      Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(origin: OriginFor<T>, instruction: OutInstructionWithBalance) -> DispatchResult {
      let from = ensure_signed(origin)?;

      if instruction.balance.coin == Coin::Serai {
        Err(Error::<T>::SriBurnNotAllowed)?;
      }

      Self::burn_internal(&from, instruction.balance, Some(instruction.instruction))?;
      Ok(())
    }
  }

  impl<T: Config> OnChargeTransaction<T> for Pallet<T> {
    type Balance = SubstrateAmount;
    type LiquidityInfo = Option<SubstrateAmount>;

    fn withdraw_fee(
      who: &T::AccountId,
      _call: &T::RuntimeCall,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      fee: Self::Balance,
      _tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
      if fee == 0 {
        return Ok(None);
      }

      let balance = Balance { coin: Coin::Serai, amount: Amount(fee) };
      match Self::transfer_internal(who, &FEE_ACCOUNT.into(), balance) {
        Err(_) => Err(InvalidTransaction::Payment.into()),
        Ok(()) => Ok(Some(fee)),
      }
    }

    fn correct_and_deposit_fee(
      who: &T::AccountId,
      _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
      _post_info: &PostDispatchInfoOf<T::RuntimeCall>,
      corrected_fee: Self::Balance,
      _tip: Self::Balance,
      already_withdrawn: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
      if let Some(paid) = already_withdrawn {
        let refund_amount = paid.saturating_sub(corrected_fee);
        let balance = Balance { coin: Coin::Serai, amount: Amount(refund_amount) };
        Self::transfer_internal(&FEE_ACCOUNT.into(), who, balance)
          .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
      }
      Ok(())
    }
  }
}

pub use pallet::*;
