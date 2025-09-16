#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use serai_primitives::balance::ExternalBalance;

/// The decider for if a mint is allowed or not.
pub trait AllowMint {
  /// Whether or not the mint of the specified coins is allowed.
  fn is_allowed(balance: &ExternalBalance) -> bool;
}

/// An `AllowMint` implementor which always returns true.
pub struct AlwaysAllowMint;
impl AllowMint for AlwaysAllowMint {
  fn is_allowed(_: &ExternalBalance) -> bool {
    true
  }
}

#[allow(clippy::cast_possible_truncation)]
#[frame_support::pallet]
mod pallet {
  use core::any::TypeId;
  use alloc::vec::Vec;

  use sp_core::sr25519::Public;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_primitives::{coin::*, balance::*, instructions::OutInstructionWithBalance};

  use super::*;

  /// The instance used to represent coins on the Serai network.
  ///
  /// This would either be SRI itself or the sriXYZ coins swappable via pools.
  pub struct CoinsInstance;
  /// The instance used to represent liquidity tokens on the Serai network.
  ///
  /// Coin::XYZ would be considered as the liquidity token for the Coin::SRI - Coin::XYZ pool.
  pub struct LiquidityTokensInstance;

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config<I: 'static = ()>: frame_system::Config<AccountId = Public> {
    /// What decides if mints are allowed.
    type AllowMint: AllowMint;
  }

  /// The genesis state to use for this pallet.
  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config<I>, I: 'static = ()> {
    /// The balances to initiate the state with.
    ///
    /// This is useful for test networks where it's desirable to have some coins available
    /// immediately.
    pub accounts: Vec<(T::AccountId, Balance)>,
    /// PhantomData to bind `I`.
    pub _instance: PhantomData<I>,
  }

  impl<T: Config<I>, I: 'static> Default for GenesisConfig<T, I> {
    fn default() -> Self {
      GenesisConfig { accounts: Default::default(), _instance: Default::default() }
    }
  }

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T, I = ()> {
    /// The mint wasn't allowed.
    MintNotAllowed,
    /// The amount an account had overflowed.
    AmountOverflowed,
    /// The account didn't have enough coins for this operation.
    NotEnoughCoins,
    /// An Instruction was specified with a Burn when that's unsupported.
    BurnWithInstructionNotAllowed,
  }

  /// An event emitted.
  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config<I>, I: 'static = ()> {
    /// Coins were minted.
    Mint {
      /// The account minted to.
      to: Public,
      /// The balance minted.
      balance: Balance,
    },
    /// Coins were transferred.
    Transfer {
      /// The account transferred from.
      from: Public,
      /// The account transferred to.
      to: Public,
      /// The balance transferred.
      balance: Balance,
    },
    /// Coins were burnt.
    Burn {
      /// The account burnt from.
      from: Public,
      /// The balance burnt.
      balance: Balance,
    },
    /// Coins were burnt with an instruction.
    BurnWithInstruction {
      /// The account burnt from.
      from: Public,
      /// The instruction, and associated balance.
      instruction: OutInstructionWithBalance,
    },
  }

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T, I = ()>(_);

  /// The amount of coins each account has.
  // Identity is used as the second key's hasher due to Coin being a small, fixed-space ID.
  #[pallet::storage]
  type Balances<T: Config<I>, I: 'static = ()> =
    StorageDoubleMap<_, Blake2_128Concat, Public, Identity, Coin, Amount, ValueQuery>;

  /// The total supply of each coin.
  #[pallet::storage]
  type Supply<T: Config<I>, I: 'static = ()> = StorageMap<_, Identity, Coin, Amount, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config<I>, I: 'static> BuildGenesisConfig for GenesisConfig<T, I> {
    fn build(&self) {
      // initialize the genesis accounts
      for (account, balance) in &self.accounts {
        Pallet::<T, I>::mint(*account, *balance).unwrap();
      }
    }
  }

  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    /// Returns the balance of `coin` for the specified account.
    pub fn balance(
      of: impl scale::EncodeLike<Public>,
      coin: impl scale::EncodeLike<Coin>,
    ) -> Amount {
      Balances::<T, I>::get(of, coin)
    }

    /// Returns the supply of `coin`.
    pub fn supply(coin: impl scale::EncodeLike<Coin>) -> Amount {
      Supply::<T, I>::get(coin)
    }

    fn decrease_balance_internal(from: Public, balance: Balance) -> Result<(), Error<T, I>> {
      let coin = &balance.coin;

      // sub amount from account
      let new_amount =
        (Self::balance(from, coin) - balance.amount).ok_or(Error::<T, I>::NotEnoughCoins)?;

      // save
      if new_amount == Amount(0) {
        Balances::<T, I>::remove(from, coin);
      } else {
        Balances::<T, I>::set(from, coin, new_amount);
      }
      Ok(())
    }

    fn increase_balance_internal(to: Public, balance: Balance) -> Result<(), Error<T, I>> {
      let coin = &balance.coin;

      // add amount to account
      let new_amount =
        (Self::balance(to, coin) + balance.amount).ok_or(Error::<T, I>::AmountOverflowed)?;

      // save
      Balances::<T, I>::set(to, coin, new_amount);
      Ok(())
    }

    /// Mint `balance` to the given account.
    ///
    /// Errors if any amount overflows.
    pub fn mint(to: Public, balance: Balance) -> Result<(), Error<T, I>> {
      {
        // If this is an external coin, check if we can mint it
        let external_balance = ExternalBalance::try_from(balance);
        let can_mint_external = external_balance.as_ref().map(T::AllowMint::is_allowed);
        // If it was native to the Serai network, we can always mint it
        let can_mint = can_mint_external.unwrap_or(true);
        if !can_mint {
          Err(Error::<T, I>::MintNotAllowed)?;
        }
      }

      // update the balance
      Self::increase_balance_internal(to, balance)?;

      // update the supply
      let new_supply = (Supply::<T, I>::get(balance.coin) + balance.amount)
        .ok_or(Error::<T, I>::AmountOverflowed)?;
      Supply::<T, I>::set(balance.coin, new_supply);

      Self::deposit_event(Event::Mint { to, balance });
      Ok(())
    }

    /// Burn `balance` from the specified account.
    fn burn_internal(from: Public, balance: Balance) -> Result<(), Error<T, I>> {
      // update the balance
      Self::decrease_balance_internal(from, balance)?;

      // update the supply
      Supply::<T, I>::mutate(balance.coin, |supply| {
        // We can unwrap here as we're burning an amount legitimately in the system (per successful
        // decrease), so the supply must be greater than this value
        let new_supply = (*supply - balance.amount).unwrap();
        *supply = new_supply;
      });

      // We don't emit the event here, but rather at the call-site, due to being unsure if we
      // should emit `Burn` or `BurnWithInstruction`

      Ok(())
    }

    /// Transfer `balance` from `from` to `to`.
    pub fn transfer_fn(from: Public, to: Public, balance: Balance) -> Result<(), Error<T, I>> {
      // update balances of accounts
      Self::decrease_balance_internal(from, balance)?;
      Self::increase_balance_internal(to, balance)?;
      Self::deposit_event(Event::Transfer { from, to, balance });
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    /// Transfer `balance` from the signer to `to`.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer(origin: OriginFor<T>, to: Public, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::transfer_fn(from, to, balance)?;
      Ok(())
    }

    /// Burn `balance` from the signer.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(origin: OriginFor<T>, balance: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::burn_internal(from, balance)?;
      Self::deposit_event(Event::Burn { from, balance });
      Ok(())
    }

    /// Burn `balance` from the signer with `instruction`.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn_with_instruction(
      origin: OriginFor<T>,
      instruction: OutInstructionWithBalance,
    ) -> DispatchResult {
      // Only allow specifying an instruction if this is Coins, not LiquidityTokens
      if TypeId::of::<I>() != TypeId::of::<CoinsInstance>() {
        Err(Error::<T, I>::BurnWithInstructionNotAllowed)?;
      }

      let from = ensure_signed(origin)?;
      Self::burn_internal(from, instruction.balance.into())?;
      Self::deposit_event(Event::BurnWithInstruction { from, instruction });
      Ok(())
    }
  }
}

pub use pallet::*;
