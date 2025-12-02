#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

#[cfg(test)]
mod mock;

#[expect(clippy::cast_possible_truncation)]
#[frame_support::pallet]
mod pallet {
  use alloc::vec::Vec;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_abi::{
    primitives::{
      prelude::*,
      dex::{Error as PrimitivesError, Reserves, Premise},
    },
    dex::Event,
  };

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;
  type LiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::LiquidityTokensInstance>;

  use super::*;

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
  {
  }

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T> {
    /// The effected/would-be-used liquidity is invalid.
    InvalidLiquidity,
    /// An arithmetic overflow occurred.
    Overflow,
    /// An arithmetic underflow occured.
    Underflow,
    /// The requested swap wasn't satisfied.
    Unsatisfied,
    /// The swap was from the coin it's to.
    FromToSelf,
  }

  impl<T> From<PrimitivesError> for Error<T> {
    fn from(error: PrimitivesError) -> Error<T> {
      match error {
        PrimitivesError::Overflow => Error::Overflow,
        PrimitivesError::Underflow => Error::Underflow,
        PrimitivesError::KInvariant => Error::Unsatisfied,
      }
    }
  }

  #[pallet::storage]
  type LpFeeInThousandths<T: Config> = StorageMap<_, Identity, ExternalCoin, u8, OptionQuery>;

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    fn emit_event(event: Event) {
      Core::<T>::emit_event(event)
    }
  }

  /// The minimum amount of liquidity allowed to be initially added.
  ///
  /// This should be sufficiently low it isn't inaccessible, yet sufficiently high that future
  /// additions can be reasonably grained when their share of the new supply is calculated.
  const MINIMUM_LIQUIDITY: u64 = 1 << 16;

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Add liquidity.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn add_liquidity(
      origin: OriginFor<T>,
      external_coin: ExternalCoin,
      sri_intended: Amount,
      external_coin_intended: Amount,
      sri_minimum: Amount,
      external_coin_minimum: Amount,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;

      let pool = serai_abi::dex::address(external_coin);
      let supply = LiquidityTokens::<T>::supply(Coin::from(external_coin)).0;

      let (sri_actual, external_coin_actual, liquidity) = if supply == 0 {
        let sri_actual = sri_intended;
        let external_coin_actual = external_coin_intended;
        /*
          The best way to explain this is to first consider how would one would write shares of a
          liquidity pool with only a single coin (however purposeless that may be). The immediate
          suggestion would simply be to use the amount of the singular coin initially added as the
          initial amount of shares, with further shares being distributed pro-rata as further
          liquidity is added. This inherently has the amount of liquidity tokens approximate the
          magnitude and scale of the underlying coin.

          When we scale the two-coin case, this methodology no longer immediately applies. The
          solution here is to take the product, and then the square root, of the two values. This
          provides a magnitude/scale of the liquidity tokens approximately in-between both coins.
        */
        let liquidity = (u128::from(sri_actual.0) * u128::from(external_coin_actual.0)).isqrt();
        let liquidity = Amount(u64::try_from(liquidity).map_err(|_| Error::<T>::Overflow)?);
        if liquidity.0 < MINIMUM_LIQUIDITY {
          Err(Error::<T>::InvalidLiquidity)?;
        }
        (sri_intended, external_coin_intended, liquidity)
      } else {
        let reserves = Reserves {
          sri: Coins::<T>::balance(pool, Coin::Serai),
          external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
        };

        let (sri_actual, external_coin_actual) = {
          let (sri_optimal, external_coin_optimal) = (
            Premise::establish(Coin::from(external_coin), Coin::Serai)
              .expect("ext, sri satisfies sri ^ sri")
              .quote_for_in(reserves, external_coin_intended)
              .map_err(Error::<T>::from)?,
            Premise::establish(Coin::Serai, Coin::from(external_coin))
              .expect("sri, ext satisfies sri ^ sri")
              .quote_for_in(reserves, sri_intended)
              .map_err(Error::<T>::from)?,
          );
          if sri_optimal < sri_intended {
            if sri_optimal < sri_minimum {
              Err(Error::<T>::Unsatisfied)?;
            }
            (sri_optimal, external_coin_intended)
          } else {
            if external_coin_optimal < external_coin_minimum {
              Err(Error::<T>::Unsatisfied)?;
            }
            (sri_intended, external_coin_optimal)
          }
        };

        let liquidity = {
          let supply = u128::from(supply);
          let sri_liquidity =
            u64::try_from((u128::from(sri_actual.0) * supply) / u128::from(reserves.sri.0))
              .map_err(|_| Error::<T>::Overflow)?;
          let external_coin_liquidity = u64::try_from(
            (u128::from(external_coin_actual.0) * supply) / u128::from(reserves.external_coin.0),
          )
          .map_err(|_| Error::<T>::Overflow)?;
          Amount(sri_liquidity.min(external_coin_liquidity))
        };

        if liquidity == Amount(0) {
          Err(Error::<T>::Unsatisfied)?;
        }

        (sri_actual, external_coin_actual, liquidity)
      };

      Coins::<T>::transfer_fn(
        from,
        pool.into(),
        Balance { coin: Coin::Serai, amount: sri_actual },
      )?;
      Coins::<T>::transfer_fn(
        from,
        pool.into(),
        Balance { coin: Coin::from(external_coin), amount: external_coin_actual },
      )?;
      let liquidity_tokens = ExternalBalance { coin: external_coin, amount: liquidity };
      LiquidityTokens::<T>::mint(from, liquidity_tokens.into())?;

      Self::emit_event(Event::LiquidityAddition {
        recipient: from.into(),
        liquidity_tokens,
        sri_amount: sri_actual,
        external_coin_amount: external_coin_actual,
      });

      Ok(())
    }

    /// Transfer these liquidity tokens to the specified address.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer_liquidity(
      origin: OriginFor<T>,
      to: SeraiAddress,
      liquidity_tokens: ExternalBalance,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;
      LiquidityTokens::<T>::transfer_fn(from, to.into(), liquidity_tokens.into())?;

      Self::emit_event(Event::LiquidityTransfer { from: from.into(), to, liquidity_tokens });

      Ok(())
    }

    /// Remove liquidity.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn remove_liquidity(
      origin: OriginFor<T>,
      liquidity_tokens: ExternalBalance,
      sri_minimum: Amount,
      external_coin_minimum: Amount,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;

      let external_coin = liquidity_tokens.coin;
      let pool = serai_abi::dex::address(external_coin);
      let supply = LiquidityTokens::<T>::supply(Coin::from(external_coin)).0;
      if supply.saturating_sub(liquidity_tokens.amount.0) < MINIMUM_LIQUIDITY {
        Err(Error::<T>::InvalidLiquidity)?;
      }
      let supply = u128::from(supply);

      let reserves = Reserves {
        sri: Coins::<T>::balance(pool, Coin::Serai),
        external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
      };
      let sri_amount =
        (u128::from(liquidity_tokens.amount.0) * u128::from(reserves.sri.0)) / supply;
      let sri_amount = Amount(u64::try_from(sri_amount).map_err(|_| Error::<T>::Overflow)?);
      let external_coin_amount =
        (u128::from(liquidity_tokens.amount.0) * u128::from(reserves.external_coin.0)) / supply;
      let external_coin_amount =
        Amount(u64::try_from(external_coin_amount).map_err(|_| Error::<T>::Overflow)?);
      if (sri_amount < sri_minimum) || (external_coin_amount < external_coin_minimum) {
        Err(Error::<T>::Unsatisfied)?;
      }

      LiquidityTokens::<T>::burn_fn(from, liquidity_tokens.into())?;
      Coins::<T>::transfer_fn(
        from,
        pool.into(),
        Balance { coin: Coin::Serai, amount: sri_amount },
      )?;
      Coins::<T>::transfer_fn(
        from,
        pool.into(),
        Balance { coin: Coin::from(external_coin), amount: external_coin_amount },
      )?;

      Self::emit_event(Event::LiquidityRemoval {
        from: from.into(),
        liquidity_tokens,
        sri_amount,
        external_coin_amount,
      });

      Ok(())
    }

    /// Swap an exact amount of coins.
    #[pallet::call_index(3)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn swap(
      origin: OriginFor<T>,
      coins_to_swap: Balance,
      minimum_to_receive: Balance,
    ) -> DispatchResult {
      let origin = SeraiAddress::from(ensure_signed(origin)?);

      let mut transfer_from = origin;
      let mut next_amount = coins_to_swap.amount;

      let swaps = Premise::route(coins_to_swap.coin, minimum_to_receive.coin)
        .ok_or(Error::<T>::FromToSelf)?;
      let mut deltas = Vec::with_capacity(swaps.len() + 1);
      for swap in &swaps {
        let external_coin = swap.external_coin();
        let pool = serai_abi::dex::address(external_coin);

        // Fetch the pool's reserves
        let reserves = Reserves {
          sri: Coins::<T>::balance(pool, Coin::Serai),
          external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
        };
        if (reserves.sri == Amount(0)) || (reserves.external_coin == Amount(0)) {
          Err(Error::<T>::InvalidLiquidity)?;
        }

        // Transfer from the prior (the originating account or pool) to the current pool
        /*
          This is impossible to reach, yet would cause the amount _yet to be transferred out_ to
          be credited both as part of the reserves _and_ the amount in if violated.
        */
        assert!(transfer_from != pool, "swap routed from a coin to itself");
        let delta = Balance { coin: swap.r#in(), amount: next_amount };
        Coins::<T>::transfer_fn(transfer_from.into(), pool.into(), delta)?;
        deltas.push(delta);

        // Update the current status
        transfer_from = pool;
        next_amount = swap.quote_for_in(reserves, next_amount).map_err(Error::<T>::from)?;
      }

      // Check the amount meets the expectation
      if next_amount.0 < minimum_to_receive.amount.0 {
        Err(Error::<T>::Unsatisfied)?;
      }

      // Transfer the resulting coins to the origin
      let delta = Balance { coin: minimum_to_receive.coin, amount: next_amount };
      Coins::<T>::transfer_fn(transfer_from.into(), origin.into(), delta)?;
      deltas.push(delta);

      Self::emit_event(Event::Swap { from: origin, deltas });

      Ok(())
    }

    /// Swap for an exact amount of coins.
    #[pallet::call_index(4)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn swap_for(
      origin: OriginFor<T>,
      coins_to_receive: Balance,
      maximum_to_swap: Balance,
    ) -> DispatchResult {
      let origin = SeraiAddress::from(ensure_signed(origin)?);

      let mut transfer_to = origin;
      let mut next_amount = coins_to_receive.amount;

      let swaps = Premise::route(maximum_to_swap.coin, coins_to_receive.coin)
        .ok_or(Error::<T>::FromToSelf)?;
      let mut deltas = Vec::with_capacity(swaps.len() + 1);
      let mut i = swaps.len();
      while {
        i -= 1;
        let swap = swaps[i];

        let external_coin = swap.external_coin();
        let pool = serai_abi::dex::address(external_coin);

        // Fetch the pool's reserves
        let reserves = Reserves {
          sri: Coins::<T>::balance(pool, Coin::Serai),
          external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
        };

        /*
          Transfer the output requested.

          While this violates the traditional Checks-Effects-Interactions pattern, in a way
          favoring the caller, this function is within a `transactional` layer
          (due to being a call) making all its DB operations only persisted upon success.
        */
        /*
          This is impossible to reach, yet ensures the amount not yet transferred in isn't
          excluded when determining the reserves on the next iteration.
        */
        assert!(transfer_to != pool, "swap routed to a coin from itself");
        let delta = Balance { coin: swap.out(), amount: next_amount };
        Coins::<T>::transfer_fn(pool.into(), transfer_to.into(), delta)?;
        deltas.push(delta);

        transfer_to = pool;
        next_amount = swap.quote_for_out(reserves, next_amount).map_err(Error::<T>::from)?;

        i != 0
      } {}

      // Check the amount meets the expectation
      if next_amount.0 > maximum_to_swap.amount.0 {
        Err(Error::<T>::Unsatisfied)?;
      }

      // Transfer the necessary coins from the origin
      let delta = Balance { coin: maximum_to_swap.coin, amount: next_amount };
      Coins::<T>::transfer_fn(origin.into(), transfer_to.into(), delta)?;
      deltas.push(delta);

      deltas.reverse();
      Self::emit_event(Event::Swap { from: origin, deltas });

      Ok(())
    }
  }
}

pub use pallet::*;
