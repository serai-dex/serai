#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;

use serai_abi::primitives::balance::Balance;

/// The decider for if a mint is allowed or not.
pub trait AllowMint {
  /// Whether or not the mint of the specified coins is allowed.
  fn is_allowed(balance: &Balance) -> bool;
}

/// An `AllowMint` implementor which always returns true.
pub struct AlwaysAllowMint;
impl AllowMint for AlwaysAllowMint {
  fn is_allowed(_: &Balance) -> bool {
    true
  }
}

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned,
  clippy::disallowed_methods
)]
#[frame_support::pallet]
mod pallet {
  use core::any::TypeId;
  use alloc::vec::Vec;

  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use serai_abi::{
    primitives::{
      address::SeraiAddress, coin::*, balance::*, instructions::OutInstructionWithBalance,
    },
    coins::Event,
  };

  use super::*;

  /// The weights for the pallet.
  pub trait Weights {
    /// The weight for a transfer.
    fn transfer() -> Weight;
    /// The weight for a burn.
    fn burn() -> Weight;
    /// The weight for a burn with an `OutInstruction`.
    fn burn_with_instruction() -> Weight;
  }

  /// A shimmed set of weights, returning zero.
  ///
  /// This is NOT safe for usage in a production system and is provided only for testing purposes.
  impl Weights for () {
    fn transfer() -> Weight {
      Weight::zero()
    }
    fn burn() -> Weight {
      Weight::zero()
    }
    fn burn_with_instruction() -> Weight {
      Weight::zero()
    }
  }

  /// The instance used to represent coins on the Serai network.
  #[derive(Default)]
  pub struct CoinsInstance;
  /// The instance used to represent liquidity tokens on the Serai network.
  ///
  /// `ExternalCoin::Xyz` would be considered as the liquidity token for the
  /// `Coin::Serai - ExternalCoin::Xyz` pool.
  #[derive(Default)]
  pub struct LiquidityTokensInstance;
  /// The instance used to represent genesis liquidity on the Serai network.
  ///
  /// `ExternalCoin::Xyz` would be considered as the genesis liquidity token for the
  /// `Coin::Serai - ExternalCoin::Xyz` pool.
  #[derive(Default)]
  pub struct GenesisLiquidityTokensInstance;

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config<I: 'static = ()>:
    frame_system::Config<AccountId = SeraiAddress> + serai_core_pallet::Config
  {
    /// What decides if mints are allowed.
    type AllowMint: AllowMint;
    /// The weights for this pallet.
    type Weights: Weights;
  }

  /// The genesis state to use for this pallet.
  #[pallet::genesis_config]
  #[derive(Clone, Debug)]
  pub struct GenesisConfig<T: Config<I>, I: 'static = ()> {
    /// The balances to initiate the state with.
    ///
    /// This is useful for test networks where it's desirable to have some coins available
    /// immediately.
    pub accounts: Vec<(T::AccountId, Balance)>,
    /// `PhantomData` to bind `I`.
    pub _instance: PhantomData<I>,
  }
  impl<T: Config<I>, I: 'static> Default for GenesisConfig<T, I> {
    fn default() -> Self {
      Self { accounts: Default::default(), _instance: PhantomData }
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

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T, I = ()>(_);

  /// The amount of coins each account has.
  // `Identity` is used as the second key's hasher due to `Coin` being small, with a static range.
  #[pallet::storage]
  type Balances<T: Config<I>, I: 'static = ()> =
    StorageDoubleMap<_, Blake2_128Concat, SeraiAddress, Identity, Coin, Amount, ValueQuery>;

  /// The total supply of each coin.
  ///
  /// This represents the supply as an `Amount`, the type generally used for representing amounts
  /// within the Serai protocol. While logical, the usage of the _same type_ is specifically used
  /// to enforce an invariant that _no_ balance is _not_ representable within an `Amount` (as any
  /// balance will be less than the supply, which can be so represented).
  ///
  /// This is not just an internal variant but is _guaranteed_ to all consumers. This allows
  /// consumers to perform logic regarding balances with certainty they won't panic, so long as the
  /// balances themselves are valid.
  #[pallet::storage]
  type Supply<T: Config<I>, I: 'static = ()> = StorageMap<_, Identity, Coin, Amount, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config<I>, I: 'static> BuildGenesisConfig for GenesisConfig<T, I> {
    fn build(&self) {
      for (account, balance) in &self.accounts {
        Pallet::<T, I>::mint(*account, *balance).unwrap();
      }
    }
  }

  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    /// Emit an event.
    ///
    /// This is a NOP for all instances which aren't `CoinsInstance`, as corresponding to
    /// [`serai_abi::coins`]. Other instances are expected to have their own frontends/interfaces
    /// with their own events.
    fn emit_event(event: Event) {
      if TypeId::of::<I>() == TypeId::of::<CoinsInstance>() {
        serai_core_pallet::Pallet::<T>::emit_event(event)
      }
    }

    /// Returns the balance of `coin` for the specified account.
    pub fn balance(
      of: impl scale::EncodeLike<SeraiAddress>,
      coin: impl scale::EncodeLike<Coin>,
    ) -> Amount {
      Balances::<T, I>::get(of, coin)
    }

    /// Returns the supply of `coin`.
    pub fn supply(coin: impl scale::EncodeLike<Coin>) -> Amount {
      Supply::<T, I>::get(coin)
    }

    fn decrease_balance_internal(from: SeraiAddress, balance: Balance) -> Result<(), Error<T, I>> {
      let coin = &balance.coin;

      let new_amount =
        (Self::balance(from, coin) - balance.amount).ok_or(Error::<T, I>::NotEnoughCoins)?;

      if new_amount == Amount(0) {
        Balances::<T, I>::remove(from, coin);
      } else {
        Balances::<T, I>::set(from, coin, new_amount);
      }
      Ok(())
    }

    fn increase_balance_internal(to: SeraiAddress, balance: Balance) -> Result<(), Error<T, I>> {
      // This ensures if someone is transferred `0`, they do not have a storage entry created.
      if balance.amount == Amount(0) {
        return Ok(());
      }

      let coin = &balance.coin;

      let new_amount =
        (Self::balance(to, coin) + balance.amount).ok_or(Error::<T, I>::AmountOverflowed)?;

      Balances::<T, I>::set(to, coin, new_amount);
      Ok(())
    }

    /// Mint `balance` to the given account.
    ///
    /// This will emit an event when, and only when, `I = CoinsInstance`.
    ///
    /// This will error if any amount overflows.
    ///
    /// This function is atomic. It will either error with no changes to the state or succeed with
    /// all expected effects.
    pub fn mint(to: SeraiAddress, coins: Balance) -> Result<(), Error<T, I>> {
      if !T::AllowMint::is_allowed(&coins) {
        Err(Error::<T, I>::MintNotAllowed)?;
      }

      // Update the supply
      let new_supply =
        (Supply::<T, I>::get(coins.coin) + coins.amount).ok_or(Error::<T, I>::AmountOverflowed)?;
      Supply::<T, I>::set(coins.coin, new_supply);

      /*
        Update the balance, which we can assume will succeed as no balance will exceed the supply.

        The usage of `expect` here lets us assert this function is atomic without using a dedicated
        transaction within the database. Alternatively, we could rewrite this to follow CEI and
        check the supply, before checking the new balance, before writing both, yet that'd prevent
        reusing the internal logic to increase a balance.
      */
      Self::increase_balance_internal(to, coins).expect("balance overflowed when supply didn't");

      Self::emit_event(Event::Mint { to, coins });
      Ok(())
    }

    /// Burn `coins` from `from`.
    ///
    /// This will not emit any events.
    ///
    /// This will error if any amount underflows.
    ///
    /// This function is atomic. It will either error with no changes to the state or succeed with
    /// all expected effects.
    pub fn burn_fn(from: SeraiAddress, balance: Balance) -> Result<(), Error<T, I>> {
      // Update the account's balance
      Self::decrease_balance_internal(from, balance)?;

      // Update the supply
      Supply::<T, I>::mutate_exists(balance.coin, |supply| {
        /*
          As before in `mint`, no balance could exceed the supply, here again, no balance may
          exceed the supply.

          Because we could decrease this amount from a user's balance, we must be able to do so
          from the supply.
        */
        let new_supply = (supply.unwrap_or(Amount(0)) - balance.amount)
          .expect("supply underflowed when balance didn't");
        *supply = (new_supply != Amount(0)).then_some(new_supply);
      });

      /*
        We don't emit an event here, but rather at the call-site, due to being unsure if we should
        should emit `Burn` or `BurnWithInstruction`.
      */

      Ok(())
    }

    /// Transfer `coins` from `from` to `to`.
    ///
    /// This will emit an event when, and only when, `I = CoinsInstance`.
    ///
    /// This function will error if the sender does not have a sufficient balance.
    ///
    /// This function is atomic. It will either error with no changes to the state or succeed with
    /// all expected effects.
    pub fn transfer_fn(
      from: SeraiAddress,
      to: SeraiAddress,
      coins: Balance,
    ) -> Result<(), Error<T, I>> {
      Self::decrease_balance_internal(from, coins)?;
      /*
        As an invariant, the supply at the start of this function is accurate and representable.

        This function does not modify the supply, so the supply is constantly representable for the
        execution of this function.

        Therefore, all users' balances may each be at most the supply as the function begins,
        executes, and ends, so long as no balance is counted multiple times (if we credited the
        transferred coins before performing the corresponding debited, causing an overlap period).

        This means each user's balance must be representable. As this function only errors if the
        recipient's balance overflows, it will never error.
      */
      Self::increase_balance_internal(to, coins)
        .expect("recipient's balance overflowed when the supply is in-range");

      Self::emit_event(Event::Transfer { from, to, coins });
      Ok(())
    }
  }

  /*
    The calls corresponding to [`serai_abi::coins::Call`], with the [`CoinsInstance`].

    Unfortunately, a limitation of the `pallet::call` attribute is that we must have `I` as a
    generic here and cannot solely implement these functions for [`CoinsInstance`]. For the calls
    which would still behave as expected (albeit sans events), we passthrough. For calls which
    don't have semantic sense, we explicitly error.

    These methods are additionally disallowed via `clippy` (see `/clippy.toml`) to force the caller
    to explicitly declare yes, they intentionally used _these_ functions (and not the ones above).

    We do the same for `burn_fn` as for `CoinsInstance`, `burn` should be used, not `burn_fn`.
  */
  #[pallet::call]
  impl<T: Config<I>, I: 'static> Pallet<T, I> {
    /// Transfer `balance` from the signer to `to`.
    ///
    /// This function is only intended to be called with the [`CoinsInstance`] and may have
    /// unexpected behavior otherwise.
    #[pallet::call_index(0)]
    #[pallet::weight((T::Weights::transfer(), DispatchClass::Normal))]
    pub fn transfer(origin: OriginFor<T>, to: SeraiAddress, coins: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::transfer_fn(from, to, coins)?;
      Ok(())
    }

    /// Burn `coins` from the signer.
    ///
    /// This function is only intended to be called with the [`CoinsInstance`] and may have
    /// unexpected behavior otherwise.
    #[pallet::call_index(1)]
    #[pallet::weight((T::Weights::burn(), DispatchClass::Normal))]
    pub fn burn(origin: OriginFor<T>, coins: Balance) -> DispatchResult {
      let from = ensure_signed(origin)?;
      Self::burn_fn(from, coins)?;
      Self::emit_event(Event::Burn { from, coins });
      Ok(())
    }

    /// Burn `balance` from the signer with `instruction`.
    ///
    /// This function is only intended to be called with the [`CoinsInstance`] and may have
    /// unexpected behavior otherwise.
    #[pallet::call_index(2)]
    #[pallet::weight((T::Weights::burn_with_instruction(), DispatchClass::Normal))]
    pub fn burn_with_instruction(
      origin: OriginFor<T>,
      instruction: OutInstructionWithBalance,
    ) -> DispatchResult {
      /*
        Only allow specifying an instruction if this is `Coins`, not `(Genesis)LiquidityTokens`.

        The respective frontends for these instances should never attempt to invoke this function,
        so this should be unreachable. Due to the severity of the idea of liquidity tokens being
        burnable as if they were coins, with instructions associated, it is explicitly guarded
        against however.
      */
      if TypeId::of::<I>() != TypeId::of::<CoinsInstance>() {
        Err(Error::<T, I>::BurnWithInstructionNotAllowed)?;
      }

      let from = ensure_signed(origin)?;
      Self::burn_fn(from, instruction.balance.into())?;
      Self::emit_event(Event::BurnWithInstruction { from, instruction });
      Ok(())
    }
  }
}

pub use pallet::{
  CoinsInstance, LiquidityTokensInstance, GenesisLiquidityTokensInstance, Config, GenesisConfig,
  Error, Pallet, Call, Weights,
};
#[doc(hidden)]
pub use pallet::*;
