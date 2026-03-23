#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
mod pallet {
  use core::marker::PhantomData;
  use alloc::vec::Vec;

  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

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

  /// The weights for the pallet.
  pub trait Weights {
    /// The weight for a call to `add_liquidity`.
    fn add_liquidity() -> Weight;
    /// The weight for a call to `transfer_liquidity`.
    fn transfer_liquidity() -> Weight;
    /// The weight for a call to `remove_liquidity`.
    fn remove_liquidity() -> Weight;
    /// The weight for a call to `swap`.
    ///
    /// `route_len` should be the length of the route the swap occurs via. This means it should be
    /// `1` if to/from `Coin::Serai` or `2` is neither coin is `Coin::Serai`.
    fn swap(route_len: usize) -> Weight;
    /// The weight for a call to `swap_for`.
    ///
    /// `route_len` should be the length of the route the swap occurs via. This means it should be
    /// `1` if to/from `Coin::Serai` or `2` is neither coin is `Coin::Serai`.
    fn swap_for(route_len: usize) -> Weight;
  }

  /// A shimmed set of weights, returning zero.
  ///
  /// This is NOT safe for usage in a production system and is provided only for testing purposes.
  impl Weights for () {
    fn add_liquidity() -> Weight {
      Weight::zero()
    }
    fn transfer_liquidity() -> Weight {
      Weight::zero()
    }
    fn remove_liquidity() -> Weight {
      Weight::zero()
    }
    fn swap(_route_len: usize) -> Weight {
      Weight::zero()
    }
    fn swap_for(_route_len: usize) -> Weight {
      Weight::zero()
    }
  }

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config<RuntimeOrigin: From<Option<SeraiAddress>>>
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
  {
    /// The weights for this pallet.
    type Weights: Weights;
  }

  /// The genesis state to use for this pallet.
  #[pallet::genesis_config]
  #[derive(Clone, Debug)]
  pub struct GenesisConfig<T: Config> {
    /// The fractional fee to charge for the `Coin::Serai - Coin::External(_)` liquidity pool.
    ///
    /// The value is denominated in thousandths. A value MUST be provided for every key.
    pub fees: Vec<(ExternalCoin, u8)>,
    /// Consumes the generic argument.
    pub _config: PhantomData<T>,
  }
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      Self { fees: ExternalCoin::all().map(|coin| (coin, 0)).collect(), _config: PhantomData }
    }
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
  type FeeInThousandths<T: Config> = StorageMap<_, Identity, ExternalCoin, u8, OptionQuery>;
  #[pallet::storage]
  type BurntFees<T: Config> = StorageMap<_, Identity, ExternalCoin, u128, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      let mut set = 0;
      for (coin, fee) in &self.fees {
        assert!(FeeInThousandths::<T>::get(coin).is_none());
        FeeInThousandths::<T>::insert(coin, fee);
        set += 1;
      }
      assert_eq!(
        set,
        ExternalCoin::all().count(),
        "fee parameter for liquidity pool on genesis omitted"
      );
    }
  }

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

  impl<T: Config> Pallet<T> {
    /// Receive the quote, denominated in SRI, for one unit of the external coin.
    ///
    /// This will return `None` if the pool has yet be initialized.
    ///
    /// This returns `Option<u128>` as the resulting quote, for an entire unit of the external coin
    /// (not atomic unit, but unit, as declared with [`Coin::decimals`]), may not fit within a
    /// `u64`. The exact range is `0 ..= (10.pow(external_coin.decimals()) * u64::MAX)`.
    pub fn sri_quote(external_coin: ExternalCoin) -> Option<u128> {
      if LiquidityTokens::<T>::supply(external_coin) == Amount(0) {
        None?;
      }

      let pool = serai_abi::dex::address(external_coin);
      let reserves = Reserves {
        sri: Coins::<T>::balance(pool, Coin::Serai),
        external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
      };
      // If this pool has liquidity, it _MUST_ have a non-zero amount for the external coin as
      // otherwise, we'd have `k = 0` and therefore have violated the `k` invariant.
      Some(
        (u128::from(10u64.pow(external_coin.decimals())) * u128::from(reserves.sri.0)) /
          u128::from(reserves.external_coin.0),
      )
    }

    /// Effect the fee for a swap in progress.
    ///
    /// This must be called _before and after_ the swap as the fee will only be applied when
    /// `current_coin == Coin::Serai`.
    ///
    /// When calculating for an amount _out_, the swap engine works in reverse, calculating how
    /// much must be fed _in_ to achieve the desired amount _out_. `add_fee_to_amount` allows
    /// toggling this behavior.
    ///
    /// This WILL update the storage to tally the fees accrued.
    fn effect_fee(
      external_coin: ExternalCoin,
      current_coin: Coin,
      amount: &mut Amount,
      add_fee_to_amount: bool,
    ) -> DispatchResult {
      if current_coin != Coin::Serai {
        return Ok(());
      }

      let fee_in_thousandths: u8 =
        FeeInThousandths::<T>::get(external_coin).expect("fee set and asserted on genesis");

      let fee_to_effect = if add_fee_to_amount {
        let one_thousand_minus_fee_in_thousandths = 1_000u16 - u16::from(fee_in_thousandths);
        // This won't trap as `fee_in_thousandths` is a `u8` and less than `1000`
        let new_amount = Amount(
          u64::try_from(
            (u128::from(amount.0) * 1000)
              .div_ceil(u128::from(one_thousand_minus_fee_in_thousandths)),
          )
          .map_err(|_| Error::<T>::Overflow)?,
        );
        let fee_to_effect = (new_amount - *amount).expect("added fee yet amount was lesser");
        *amount = new_amount;
        fee_to_effect
      } else {
        let fee_to_effect = Amount(
          u64::try_from((u128::from(amount.0) * u128::from(fee_in_thousandths)).div_ceil(1_000))
            .expect("fee (`u8`) exceeded 1000?"),
        );
        // This won't trap as it's a fraction of the amount itself
        amount.0 -= fee_to_effect.0;
        fee_to_effect
      };

      let fee_to_burn = Amount(fee_to_effect.0.div_ceil(2));

      BurntFees::<T>::mutate(external_coin, |burnt| {
        // This is wide to ensure it won't overflow. While we know the supply fits in a `u64`, this
        // may increase even as burns occur and the supply is reduced, making that insufficient.
        *burnt += u128::from(fee_to_burn.0);
      });

      // This is disallowed as `burn` MUST ONLY be called for `CoinsInstance`, which this does
      #[expect(clippy::disallowed_methods)]
      Coins::<T>::burn(
        Some(serai_abi::dex::address(external_coin)).into(),
        Balance { coin: Coin::Serai, amount: fee_to_burn },
      )?;

      Ok(())
    }

    /// Take the burnt fees.
    ///
    /// This does not perform any transfers of any type. This solely resets the bookkeeping entry
    /// for the burnt fees, yielding its value.
    pub fn take_burnt_fees(coin: ExternalCoin) -> u128 {
      BurntFees::<T>::take(coin)
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Add liquidity.
    #[pallet::call_index(0)]
    #[pallet::weight((<T as Config>::Weights::add_liquidity(), DispatchClass::Normal))]
    pub fn add_liquidity(
      origin: OriginFor<T>,
      external_coin: ExternalCoin,
      sri_intended: Amount,
      external_coin_intended: Amount,
      sri_minimum: Amount,
      external_coin_minimum: Amount,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;

      if (sri_minimum > sri_intended) || (external_coin_minimum > external_coin_intended) {
        Err(Error::<T>::InvalidLiquidity)?;
      }

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

        /*
          The amounts to add to the pool are determined along the curve in order to ensure the
          user's requested bounds on the valuation of one coin respective to the other is followed.
        */
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

        /*
          The actual amount of liquidity to add is determined linearly so additions of liquidity do
          not move the price in any way advantageous to whoever adds liquidity.
        */
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

        // Further check it did not resolve as zero liquidity due to unexpected changes of
        // magnitude between the time this transaction was published and included on-chain
        if liquidity == Amount(0) {
          Err(Error::<T>::Unsatisfied)?;
        }

        (sri_actual, external_coin_actual, liquidity)
      };

      Coins::<T>::transfer_fn(from, pool, Balance { coin: Coin::Serai, amount: sri_actual })?;
      Coins::<T>::transfer_fn(
        from,
        pool,
        Balance { coin: Coin::from(external_coin), amount: external_coin_actual },
      )?;
      let liquidity_tokens = ExternalBalance { coin: external_coin, amount: liquidity };

      // This MUST be done last as the desired `AllowMint` implementation will evaluate economic
      // security by the amount of coins within the pool, requiring the coins already be _in_ the
      // pool (as transferred above).
      LiquidityTokens::<T>::mint(from, liquidity_tokens.into())?;

      Self::emit_event(Event::LiquidityAddition {
        recipient: from,
        liquidity_tokens,
        sri_amount: sri_actual,
        external_coin_amount: external_coin_actual,
      });

      Ok(())
    }

    /// Transfer these liquidity tokens to the specified address.
    #[pallet::call_index(1)]
    #[pallet::weight((<T as Config>::Weights::transfer_liquidity(), DispatchClass::Normal))]
    pub fn transfer_liquidity(
      origin: OriginFor<T>,
      to: SeraiAddress,
      liquidity_tokens: ExternalBalance,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;
      LiquidityTokens::<T>::transfer_internal(from, to, liquidity_tokens.into())?;

      Self::emit_event(Event::LiquidityTransfer { from, to, liquidity_tokens });

      Ok(())
    }

    /// Remove liquidity.
    #[pallet::call_index(2)]
    #[pallet::weight((<T as Config>::Weights::remove_liquidity(), DispatchClass::Normal))]
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

      #[expect(clippy::disallowed_methods)]
      LiquidityTokens::<T>::burn_fn(from, liquidity_tokens.into())?;
      Coins::<T>::transfer_fn(pool, from, Balance { coin: Coin::Serai, amount: sri_amount })?;
      Coins::<T>::transfer_fn(
        pool,
        from,
        Balance { coin: Coin::from(external_coin), amount: external_coin_amount },
      )?;

      Self::emit_event(Event::LiquidityRemoval {
        from,
        liquidity_tokens,
        sri_amount,
        external_coin_amount,
      });

      Ok(())
    }

    /// Swap an exact amount of coins.
    #[pallet::call_index(3)]
    #[pallet::weight((<T as Config>::Weights::swap({
      if (coins_to_swap.coin == Coin::Serai) || (minimum_to_receive.coin == Coin::Serai) {
        1
      } else {
        2
      }
    }), DispatchClass::Normal))]
    pub fn swap(
      origin: OriginFor<T>,
      coins_to_swap: Balance,
      minimum_to_receive: Balance,
    ) -> DispatchResult {
      let origin = ensure_signed(origin)?;

      let mut transfer_from = origin;
      let mut next_amount = coins_to_swap.amount;

      let swaps = Premise::route(coins_to_swap.coin, minimum_to_receive.coin)
        .ok_or(Error::<T>::FromToSelf)?;
      let mut deltas = Vec::with_capacity(swaps.len() + 1);
      for swap in &swaps {
        let external_coin = swap.external_coin();
        // If the pool has recognized liquidity, it's been initialized
        if LiquidityTokens::<T>::supply(external_coin) == Amount(0) {
          Err(Error::<T>::InvalidLiquidity)?;
        }

        let pool = serai_abi::dex::address(external_coin);

        // Fetch the pool's reserves
        let reserves = Reserves {
          sri: Coins::<T>::balance(pool, Coin::Serai),
          external_coin: Coins::<T>::balance(pool, Coin::from(external_coin)),
        };

        // Transfer from the prior (the originating account or pool) to the current pool
        /*
          This is impossible to reach, yet would cause the amount _yet to be transferred out_ to
          be credited both as part of the reserves _and_ the amount in if violated.
        */
        assert!(transfer_from != pool, "swap routed from a coin to itself");
        let delta = Balance { coin: swap.r#in(), amount: next_amount };
        Coins::<T>::transfer_fn(transfer_from, pool, delta)?;
        deltas.push(delta);

        // Update the current status
        transfer_from = pool;

        // This may burn the fee, slightly changing the reserves, but we intentially don't update
        // them as we don't want the direction of the swap (and if the burn happens before or after
        // the quote) to affect the quote itself
        Self::effect_fee(external_coin, swap.r#in(), &mut next_amount, false)?;
        next_amount = swap.quote_for_in(reserves, next_amount).map_err(Error::<T>::from)?;
        Self::effect_fee(external_coin, swap.out(), &mut next_amount, false)?;
      }

      // Check the amount meets the expectation
      if next_amount.0 < minimum_to_receive.amount.0 {
        Err(Error::<T>::Unsatisfied)?;
      }

      // Transfer the resulting coins to the origin
      let delta = Balance { coin: minimum_to_receive.coin, amount: next_amount };
      Coins::<T>::transfer_fn(transfer_from, origin, delta)?;
      deltas.push(delta);

      Self::emit_event(Event::Swap { from: origin, deltas });

      Ok(())
    }

    /// Swap for an exact amount of coins.
    #[pallet::call_index(4)]
    #[pallet::weight((<T as Config>::Weights::swap({
      if (coins_to_receive.coin == Coin::Serai) || (maximum_to_swap.coin == Coin::Serai) {
        1
      } else {
        2
      }
    }), DispatchClass::Normal))]
    pub fn swap_for(
      origin: OriginFor<T>,
      coins_to_receive: Balance,
      maximum_to_swap: Balance,
    ) -> DispatchResult {
      let origin = ensure_signed(origin)?;

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
        if LiquidityTokens::<T>::supply(external_coin) == Amount(0) {
          Err(Error::<T>::InvalidLiquidity)?;
        }

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
        Coins::<T>::transfer_fn(pool, transfer_to, delta)?;
        deltas.push(delta);

        transfer_to = pool;

        Self::effect_fee(external_coin, swap.out(), &mut next_amount, true)?;
        next_amount = swap.quote_for_out(reserves, next_amount).map_err(Error::<T>::from)?;
        Self::effect_fee(external_coin, swap.r#in(), &mut next_amount, true)?;

        i != 0
      } {}

      // Check the amount meets the expectation
      if next_amount.0 > maximum_to_swap.amount.0 {
        Err(Error::<T>::Unsatisfied)?;
      }

      // Transfer the necessary coins from the origin
      let delta = Balance { coin: maximum_to_swap.coin, amount: next_amount };
      Coins::<T>::transfer_fn(origin, transfer_to, delta)?;
      deltas.push(delta);

      deltas.reverse();
      Self::emit_event(Event::Swap { from: origin, deltas });

      Ok(())
    }
  }
}

pub use pallet::{Config, GenesisConfig, Error, Pallet, Call, Weights};
#[doc(hidden)]
pub use pallet::*;
