#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
mod pallet {
  use core::{marker::PhantomData, time::Duration};

  extern crate alloc;
  use alloc::vec;

  use sp_application_crypto::RuntimePublic as _;

  use frame_support::{sp_runtime, pallet_prelude::*, dispatch::RawOrigin};
  use frame_system::pallet_prelude::*;

  use serai_abi::{
    primitives::{
      prelude::*, BitVec, crypto::RistrettoSignature, genesis_liquidity::GenesisValues,
    },
    economic_security::EconomicSecurity as _,
    genesis_liquidity::Event,
    TransactionContext as _,
  };

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;
  type LiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::LiquidityTokensInstance>;
  type Dex<T> = serai_dex_pallet::Pallet<T>;
  type GenesisLiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::GenesisLiquidityTokensInstance>;
  type ValidatorSets<T> = serai_validator_sets_pallet::Pallet<T>;

  // These are from `specs/Economics.md`
  const GENESIS_SRI: Amount = Amount(100_000_000 * 10u64.pow(Coin::Serai.decimals()));
  const GENESIS_LIQUIDITY_TIME: Duration =
    serai_abi::primitives::constants::DAY.checked_mul(30).unwrap();
  const GENESIS_TRICKLE_FEED: u128 =
    serai_abi::primitives::constants::DAY.checked_mul(180).unwrap().as_millis();

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::GenesisLiquidityTokensInstance>
    + serai_dex_pallet::Config
    + serai_validator_sets_pallet::Config
  {
  }

  /// The first (non-genesis) block's timestamp.
  #[pallet::storage]
  type GenesisTimestamp<T: Config> = StorageValue<_, u64, OptionQuery>;
  /// If the values have been oraclized, signifying the end of the genesis period.
  #[pallet::storage]
  type Oraclized<T: Config> = StorageValue<_, (), OptionQuery>;
  /// When economic security was achieved, represented in milliseconds since the epoch.
  #[pallet::storage]
  type EconomicSecurityAchieved<T: Config> = StorageValue<_, u64, OptionQuery>;

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T> {
    /// It is after the genesis event.
    PostGenesis,
  }

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    fn emit_event(event: Event) {
      Core::<T>::emit_event(event)
    }
  }

  #[pallet::hooks] // serai-core-pallet: allow
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
      assert!(!block_number.is_zero());
      if block_number.is_one() {
        let genesis_time = Core::<T>::current_time();
        assert!(genesis_time != 0);
        GenesisTimestamp::<T>::set(Some(genesis_time));
      }

      if EconomicSecurityAchieved::<T>::get().is_none() &&
        ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security)
      {
        EconomicSecurityAchieved::<T>::set(Some(Core::<T>::current_time()));
      }

      /*
        This hook is minute. It's:
        - A conditional which evaluates to `false` for all but one block
        - A few storage reads every block until economic security, a near constant amount of work
          which can be considered as always present and not weight consumed, but capacity for
          weight never present, except for one exceptional block

        So we handwave the weight of this hook here.
      */
      Weight::zero()
    }
  }

  impl<T: Config> Pallet<T> {
    /// Add liquidity on behalf of the specified address.
    pub fn add_liquidity(
      transfer_from: SeraiAddress,
      to: SeraiAddress,
      genesis_liquidity: ExternalBalance,
    ) -> DispatchResult {
      if Oraclized::<T>::get().is_some() {
        Err(Error::<T>::PostGenesis)?;
      }

      let transfer_to = serai_abi::genesis_liquidity::address(genesis_liquidity.coin);
      Coins::<T>::transfer_fn(transfer_from, transfer_to, genesis_liquidity.into())?;

      /*
        We explicitly mint an amount equivalent to the amount added to ensure perfectly accurate
        tracking, and to let `remove_genesis_liquidity` to know how much was originally added from
        the specification of the amount of genesis liquidity being removed.
      */
      GenesisLiquidityTokens::<T>::mint(to, genesis_liquidity.into())?;
      Self::emit_event(Event::GenesisLiquidityAdded { to, genesis_liquidity });

      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Oraclize the values of the coins available on genesis, relative to BTC.
    ///
    /// This will trigger the addition of the liquidity into the pools and their initialization.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn oraclize_values(
      origin: OriginFor<T>,
      values: GenesisValues,
      signature_participants: BitVec<{ KeyShares::MAX_PER_SET_U64 }>,
      signature: RistrettoSignature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // The validity checks for this call happen in the associated `validate_unsigned`
      let _ = (signature_participants, signature);

      Oraclized::<T>::set(Some(()));

      // Initialize the pools
      {
        // First, we determine the values for each of the coins present upon genesis
        let btc = GenesisLiquidityTokens::<T>::supply(Coin::External(ExternalCoin::Bitcoin));
        let GenesisValues { ether, dai, monero } = values;
        let value = |coin: ExternalCoin, value_in_btc: Amount| {
          (u128::from(GenesisLiquidityTokens::<T>::supply(Coin::External(coin)).0) *
            u128::from(value_in_btc.0)) /
            10u128.pow(coin.decimals())
        };
        let ether = value(ExternalCoin::Ether, ether);
        let dai = value(ExternalCoin::Dai, dai);
        let monero = value(ExternalCoin::Monero, monero);

        // Then, we determine the total value and each coin's share of the total value
        let total_value = [ether, dai, monero]
          .into_iter()
          .try_fold(u128::from(btc.0), u128::checked_add)
          .ok_or(serai_dex_pallet::Error::<T>::Overflow)?;
        let sri = u128::from(GENESIS_SRI.0);
        let sri_for_coin = |value: u128| -> Result<_, serai_dex_pallet::Error<T>> {
          Ok(value.checked_mul(sri).ok_or(serai_dex_pallet::Error::<T>::Overflow)? / total_value)
        };
        let btc_sri = sri_for_coin(u128::from(btc.0))?;
        let ether_sri = sri_for_coin(ether)?;
        let dai_sri = sri_for_coin(dai)?;
        let monero_sri = sri_for_coin(monero)?;

        // Finally, we actually instantiate all of the pools
        for (external_coin, sri) in [
          (ExternalCoin::Bitcoin, btc_sri),
          (ExternalCoin::Ether, ether_sri),
          (ExternalCoin::Dai, dai_sri),
          (ExternalCoin::Monero, monero_sri),
        ] {
          let our_address = serai_abi::genesis_liquidity::address(external_coin);
          let sri = Amount(u64::try_from(sri).map_err(|_| serai_dex_pallet::Error::<T>::Overflow)?);
          Coins::<T>::mint(our_address, Balance { coin: Coin::Serai, amount: sri })?;
          let external_coin_amount =
            GenesisLiquidityTokens::<T>::supply(Coin::External(external_coin));
          serai_dex_pallet::Pallet::<T>::add_liquidity(
            RawOrigin::Signed(our_address).into(),
            external_coin,
            sri,
            external_coin_amount,
            sri,
            external_coin_amount,
          )?;
        }
        assert!(u128::from(Coins::<T>::supply(Coin::Serai).0) <= sri);
      }

      // Initialize the validator sets
      {
        // Use the current Serai set, as this _should_ represent the genesis validators
        let set = ValidatorSet {
          network: NetworkId::Serai,
          session: ValidatorSets::<T>::current_session(NetworkId::Serai)
            .expect("oraclizing values yet never genesis'd Serai"),
        };

        let amount_of_genesis_key_shares = u16::from(
          ValidatorSets::<T>::key_shares(set)
            .expect("validator set is current but doesn't have its key shares defined"),
        );

        // Even if all non-genesis validators are malicious, integrity should hold until economic
        // security so long as a single genesis validator is honest
        let target_non_genesis_validator_key_shares =
          2u16.saturating_mul(amount_of_genesis_key_shares).saturating_add(1);
        let target_non_genesis_validator_key_shares =
          KeyShares::saturating_from(target_non_genesis_validator_key_shares);

        // Ensure the requirement per key share is sane (at least 0.01% of the genesis SRI)
        const SANITY_REQUIREMENT_PER_KEY_SHARE: Amount = Amount(GENESIS_SRI.0 / 10_000);

        let mut external_stake_required = Amount(0);
        for network in ExternalNetworkId::all() {
          let requirement = ValidatorSets::<T>::network_stake_requirement(network);
          // `target_non_genesis_validator_key_shares` is non-zero by how it's calculated
          let requirement_per_key_share = Amount(
            requirement.0.div_ceil(u64::from(u16::from(target_non_genesis_validator_key_shares))),
          );
          ValidatorSets::<T>::set_allocation_per_key_share(
            network.into(),
            requirement_per_key_share.max(SANITY_REQUIREMENT_PER_KEY_SHARE),
          );

          external_stake_required = (external_stake_required + requirement)
            .ok_or(serai_dex_pallet::Error::<T>::Overflow)?;
        }

        /*
          `STAKE_DESIRED`, but with `/ (1 - SERAI_VALIDATORS_DESIRED_PERCENTAGE)` written as
          `* 6 / 5` (as both are equal to `* 1.2` given how
          `SERAI_VALIDATORS_DESIRED_PERCENTAGE = 0.2`).
        */
        let stake_desired = Amount(
          external_stake_required.0.checked_mul(6).ok_or(serai_dex_pallet::Error::<T>::Overflow)? /
            5,
        );
        let serai_validators_stake_desired = Amount(stake_desired.0 / 5);
        let serai_per_key_share = Amount(
          serai_validators_stake_desired
            .0
            .div_ceil(u64::from(u16::from(target_non_genesis_validator_key_shares))),
        );
        ValidatorSets::<T>::set_allocation_per_key_share(
          NetworkId::Serai,
          serai_per_key_share.max(SANITY_REQUIREMENT_PER_KEY_SHARE),
        );
      }

      Ok(())
    }

    /// Transfer genesis liquidity.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer_genesis_liquidity(
      origin: OriginFor<T>,
      to: SeraiAddress,
      genesis_liquidity: ExternalBalance,
    ) -> DispatchResult {
      let from = ensure_signed(origin)?;
      GenesisLiquidityTokens::<T>::transfer_fn(from, to, genesis_liquidity.into())?;
      Self::emit_event(Event::GenesisLiquidityTransferred { from, to, genesis_liquidity });
      Ok(())
    }

    /// Remove genesis liquidity.
    ///
    /// This function is not atomic in any regard. It performs checks and interactions as tells a
    /// story, even if/when further checks are required for the function as a whole. It is entirely
    /// premised on how calls within a pallet are, by default, wrapped within a transactional
    /// layer:
    ///
    /// https://github.com/serai-dex/patch-polkadot-sdk
    ///   /blob/55a9d2cf03623408ee8231b73189bbd3d1ee93d2/polkadot-sdk
    ///     /substrate/frame/support/procedural/src/pallet/expand/call.rs#L242-L246
    ///
    /// This transactional layer is only applied when dispatching a call however. If this function
    /// is called directly, it won't. This is _fine_ as it follows a general practice within the
    /// Serai codebase, that calls (and their implementing functions) are assumed to be
    /// transactional and accordingly don't have to be atomic, but it's worth noting very
    /// carefully.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn remove_genesis_liquidity(
      origin: OriginFor<T>,
      genesis_liquidity: ExternalBalance,
      sri_minimum: Amount,
      external_coin_minimum: Amount,
    ) -> DispatchResult {
      /*
        This function takes pride in not erroring under any condition, except:

        - If a called function errors, which will be propagated
        - If the pool has invalid liquidity
        - If the user's request is unsatisfied

        All arithmetic operations are explicitly handled, extensively bounded, and documented to
        why they won't trap and are sound. While this does occassionally require calls to
        `min`/`max` to ensure, these calls are logically sound and still fulfill the intended
        calculations. There's also plenty of detail to ensuring rounding errors do not favor the
        user, granting an adversary the ability to perform economic attacks.
      */

      let signer = ensure_signed(origin)?;

      let total_genesis_liquidity_prior_to_burn =
        GenesisLiquidityTokens::<T>::supply(genesis_liquidity.coin);
      // This is disallowed as `burn_fn` shouldn't be called for `CoinsInstance`, which this isn't
      #[expect(clippy::disallowed_methods)]
      GenesisLiquidityTokens::<T>::burn_fn(signer, genesis_liquidity.into())?;

      /*
        Emit the `GenesisLiquidityRemoved` event at the end of the function.

        This ensures that even if we return early, this event will be emitted. It also means this
        event will be emitted even if we return an error, but that is presumed to be caught by the
        transactional layer. If we emitted the event outright now, we'd still rely on the
        transactional layer.

        As for why we don't emit this event now, it follows how `serai_dex_pallet` emits its events
        at the _end_ of its functions, once the operations are complete.
      */
      struct GenesisLiquidityRemovedEvent<T: Config>(Event, PhantomData<T>);
      impl<T: Config> Drop for GenesisLiquidityRemovedEvent<T> {
        fn drop(&mut self) {
          Pallet::<T>::emit_event(self.0.clone());
        }
      }
      let _event = GenesisLiquidityRemovedEvent::<T>(
        Event::GenesisLiquidityRemoved { by: signer, genesis_liquidity },
        PhantomData,
      );

      let our_address = serai_abi::genesis_liquidity::address(genesis_liquidity.coin);

      // If this is prior to initializing the pools, this is a straightforward removal
      if Oraclized::<T>::get().is_none() {
        Coins::<T>::transfer_fn(our_address, signer, genesis_liquidity.into())?;
        return Ok(());
      }

      // Determine how many liquidity tokens these genesis liquidity tokens corresponded to
      let share_of_liquidity_tokens = {
        let our_liquidity_tokens =
          LiquidityTokens::<T>::balance(our_address, genesis_liquidity.coin);
        // `our_liquidity_tokens` multiplied by the ratio of these genesis liquidity tokens to all
        // The usage of a floor division here favors the protocol, as desirable
        let share_of_liquidity_tokens = (u128::from(our_liquidity_tokens.0) *
          u128::from(genesis_liquidity.amount.0))
        .checked_div(u128::from(total_genesis_liquidity_prior_to_burn.0));
        /*
          This division may fail if `total_genesis_liquidity_prior_to_burn` is `0`, which may occur
          if and only if the amount of liquidity being removed is itself `0`. Accordingly,
          normalizing the result to `0` is sane.

          We could error here but the `coins` pallet established the precedent of allowing `0`. It
          helps in that automated tooling which expects to be able to call this function for any
          sane value, and don't handle the edge-case of legitimately calculating `0`, won't
          unexpectedly error.
        */
        let share_of_liquidity_tokens = share_of_liquidity_tokens.unwrap_or(0);
        Amount(
          u64::try_from(share_of_liquidity_tokens)
            .expect("`(a * b) / c` where `b <= c` produced result `> a`"),
        )
      };

      // Fetch the pool's values
      let pool_address = serai_abi::dex::address(genesis_liquidity.coin);
      let pool_sri = Coins::<T>::balance(pool_address, Coin::Serai);
      let pool_external_coin = Coins::<T>::balance(pool_address, genesis_liquidity.coin);
      let total_liquidity_tokens = LiquidityTokens::<T>::supply(genesis_liquidity.coin);

      /*
        The amount of the external coin within the genesis liquidity being removed.

        This `expect` is valid as `serai_coins_pallet` guarantees the invariant that balances are
        less than the supply, causing `b <= c`.
      */
      let liquidity_position_external_coin = Amount(
        u64::try_from(
          (u128::from(pool_external_coin.0) * u128::from(share_of_liquidity_tokens.0))
            .checked_div(u128::from(total_liquidity_tokens.0))
            .ok_or(serai_dex_pallet::Error::<T>::InvalidLiquidity)?,
        )
        .expect("`(a * b) / c` where `b <= c` produced result `> a`"),
      );

      /*
        Apply the trickle feed, returning how much of the input should be yielded to the user.

        The result will be in the range `0 ..= amount`.
      */
      let trickle_feed = {
        /*
          Calculate our position within the trickle feed.

          This value will be `0` if pre-economic security and otherwise bounded between
          `0 ..= GENESIS_TRICKLE_FEED`, as allowing
          `position_in_trickle_feed / GENESIS_TRICKLE_FEED` to be a fraction of the additional
          coins to yield.
        */
        let position_in_trickle_feed = {
          // This subtraction won't trap due to `serai-core-pallet` (and Serai's headers)
          // guaranteeing a monotonic time.
          let time_since_economic_security_achieved = EconomicSecurityAchieved::<T>::get()
            .map(|time_achieved| u128::from(Core::<T>::current_time() - time_achieved))
            .unwrap_or(0);
          // Bound the time since achieving economic security to within the required range
          time_since_economic_security_achieved.min(GENESIS_TRICKLE_FEED)
        };

        move |amount: Amount| {
          // This won't trap so long as `GENESIS_TRICKLE_FEED != 0`
          const _GENESIS_TRICKLE_FEED_IS_NON_ZERO: () = {
            assert!(GENESIS_TRICKLE_FEED != 0);
          };
          Amount(
            u64::try_from((u128::from(amount.0) * position_in_trickle_feed) / GENESIS_TRICKLE_FEED)
              .expect("`(a * b) / c` where `b <= c` produced result `> a`"),
          )
        }
      };

      let liquidity_to_remove = {
        // Calculate the amount of the external coin to consider yielding for this liquidity
        let yieldable_external_coin = {
          /*
            Calculate how much of this external coin is additional to the initial liquidity. This is
            premised on how the genesis liquidity tokens are 1:1 with the amount originally added.
          */
          let additional_external_coin =
            (liquidity_position_external_coin - genesis_liquidity.amount).unwrap_or(Amount(0));
          (genesis_liquidity.amount.min(liquidity_position_external_coin) +
            trickle_feed(additional_external_coin))
          .expect("`c <= (a - b); (a.min(b) + c) > a`?")
        };

        /*
          We are expected to leave `liquidity_position_external_coin - yieldable_external_coin`
          within the pool for further swaps. Instead of removing the entire liquidity position, we
          only remove the liquidity tokens corresponding to `yieldable_external_coin`.

          Despite needing to use a `div_ceil` to ensure the liquidity tokens removed is sufficient
          for `yieldable_external_coin`, that would potentially remove _slightly more_ than
          yieldable. Accordingly, we use a floor div, so the rounding error remains in the pool.
        */
        Amount(
          u64::try_from(
            (u128::from(total_liquidity_tokens.0) * u128::from(yieldable_external_coin.0))
              .checked_div(u128::from(pool_external_coin.0))
              .ok_or(serai_dex_pallet::Error::<T>::InvalidLiquidity)?,
          )
          .expect(
            "yieldable external coin <= liquidity position external coin <= pool external coin",
          ),
        )
      };

      /*
        We calculated the `yieldable_external_coin` to be less than or equal to the amount of the
        external coin present in the liquidity. We then calculated `liquidity_to_remove` to be less
        than or equal to the amount necessary to remove `yieldable_external_coin`. Accordingly,
        this should _always_ round in favor of the protocol and ensure this condition holds.
      */
      let difference_in_liquidity = (share_of_liquidity_tokens - liquidity_to_remove)
        .expect("calculated genesis liquidity removal exceeding share of genesis liquidity");

      /*
        Perform the removal for the amount of external coin less than or equal to the amount
        initially calculated as yieldable (due to rounding errors).

        We use `Dex::remove_liquidity` to enforce the amount of the external coin received is
        _at least_ as much as the user requested. We do not request any minimum amount of SRI
        however, deferring that check to later within this function.
      */
      Dex::<T>::remove_liquidity(
        Some(our_address).into(),
        ExternalBalance { coin: genesis_liquidity.coin, amount: liquidity_to_remove },
        Amount(0),
        external_coin_minimum,
      )?;

      /*
        Synchronize the yieldable amount of the external coin to the actual amount removed.

        This will be slightly different than prior calculated due to rounding errors when
        determining how much liquidity to actually remove.
      */
      let yieldable_external_coin = Coins::<T>::balance(our_address, genesis_liquidity.coin);
      // Retrieve how much SRI was in the removed liquidity
      let liquidity_position_sri = Coins::<T>::balance(our_address, Coin::Serai);

      let yieldable_sri = {
        /*
          If the amount of the external coin is less than the amount originally added, yield SRI of
          of approximate value to the difference at the quote represented within the pool itself.

          This also provides grace to if the amount of external coin was truncated during a
          rounding error by now considering such truncations when determining how much SRI to
          yield.
        */
        let corresponding_sri = {
          let difference_in_external_coin =
            (genesis_liquidity.amount - yieldable_external_coin).unwrap_or(Amount(0));
          /*
            This uses the quote from the pool itself, as corresponding to the quote at the time of
            the liquidity being removed. The fact this uses an exact quote does technically mean
            this amount is insufficient to swap to this much of the external coin, as beginning any
            swap to the external coin will raise the quote within the AMM. This is accepted as the
            slippage of such a swap.

            The usage of a `div`, not a `div_ceil`, does mean the user bears the rounding error.
            This is intentional as rounding errors should always favor the protocol to ensure its
            health. If the protocol is unhealthy, so would be its users.

            `pool_sri / pool_external_coin` is the quote in SRI for how much an atomic unit of the
            external coin is valued at.
          */
          (u128::from(difference_in_external_coin.0) * u128::from(pool_sri.0))
            .checked_div(u128::from(pool_external_coin.0))
            .ok_or(serai_dex_pallet::Error::<T>::InvalidLiquidity)?
        };

        /*
          Ensure the amount of SRI we can consider corresponding to a difference between the
          initial addition and current removal does not exceed the amount of SRI from the removed
          liquidity.

          We left the prior `corresponding_sri` as a `u128`, instead of attempting to convert it to
          an `Amount` and returning an error on overflow, because we perform this reduction here
          which guarantees the output will fit in an `Amount`.
        */
        let corresponding_sri = corresponding_sri.min(u128::from(liquidity_position_sri.0));
        let corresponding_sri =
          Amount(u64::try_from(corresponding_sri).expect("`b < u64::MAX; a.min(b) > u64::MAX`?"));

        let additional_sri = (liquidity_position_sri - corresponding_sri).unwrap();

        /*
          `corresponding_sri + additional_sri = liquidity_position_sri`, which fits in an `Amount`,
          so this `expect` will hold so long as `trickle_feed` returns an amount in the range
          `0 ..= additional_sri`, as it's defined to.
        */
        (corresponding_sri + trickle_feed(additional_sri))
          .expect("`a = l - c; t < 1; c + (t * a) > l`?")
      };

      /*
        Now that we know how much we should yield, and taken its minimum with how much we _can_
        yield, we can finally enforce the user-specified `sri_minimum`.

        We could have (redundantly) specified `sri_minimum` when we called `remove_liquidity`,
        terminating execution early if even back then, the amount would be insufficient. Specifying
        a minimum of `Amount(0)` made it clear the check was not being enforced at that time
        however, and makes it clear this is THE check (not a redundancy/incorrectly encoded copy of
        the same check/straggler from some reorganization of the code).
      */
      if yieldable_sri < sri_minimum {
        Err(serai_dex_pallet::Error::<T>::Unsatisfied)?;
      }

      /*
        Transfer the remainder of this position's liquidity tokens to the pool's address,
        representing Protocol-Owned Liquidity. This ensures these coins will remain available via
        the pool and able to be swapped.
      */
      LiquidityTokens::<T>::transfer_fn(
        our_address,
        pool_address,
        (ExternalBalance { coin: genesis_liquidity.coin, amount: difference_in_liquidity }).into(),
      )?;

      // Burn the SRI which is from the incomplete trickle feed
      // This is disallowed as `burn` MUST ONLY be called for `CoinsInstance`, which this does
      #[expect(clippy::disallowed_methods)]
      Coins::<T>::burn(
        Some(our_address).into(),
        Balance {
          coin: Coin::Serai,
          amount: (liquidity_position_sri - yieldable_sri)
            .expect("ensured `yieldable_sri <= liquidity_position_sri` but couldn't subtract it?"),
        },
      )?;

      // Transfer the yieldable SRI to the user
      Coins::<T>::transfer_fn(
        our_address,
        signer,
        Balance { coin: Coin::Serai, amount: yieldable_sri },
      )?;

      // Transfer the external coin to the user
      Coins::<T>::transfer_fn(
        our_address,
        signer,
        (ExternalBalance { coin: genesis_liquidity.coin, amount: yieldable_external_coin }).into(),
      )?;

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      match call {
        Call::oraclize_values { values, signature_participants, signature } => {
          // Verify this hasn't already happened
          if Oraclized::<T>::get().is_some() {
            Err(InvalidTransaction::Stale)?;
          }

          // Verify the time
          {
            let Some(minimum_timestamp) = GenesisTimestamp::<T>::get()
              .and_then(|time| Duration::from_millis(time).checked_add(GENESIS_LIQUIDITY_TIME))
            else {
              Err(InvalidTransaction::Future)?
            };
            if Duration::from_millis(Core::<T>::current_time()) < minimum_timestamp {
              Err(InvalidTransaction::Future)?;
            }
          }

          // Verify the signature
          {
            // Use the current Serai set, as this _should_ represent the genesis validators. The
            // exact reasoning on this assumption is documented in this crate's README.
            let set = ValidatorSet {
              network: NetworkId::Serai,
              session: ValidatorSets::<T>::current_session(NetworkId::Serai)
                .expect("oraclizing values yet never genesis'd Serai"),
            };

            let mut signature_participants = signature_participants.into_iter();
            let mut selected_validators = ValidatorSets::<T>::selected_validators(set);

            let mut total_key_shares = 0;
            let mut participating_key_shares = 0;
            let mut participating_keys = vec![];
            for (participating, (validator, key_shares)) in
              (&mut signature_participants).zip(&mut selected_validators)
            {
              total_key_shares += u16::from(key_shares);
              if *participating {
                participating_key_shares += u16::from(key_shares);
                participating_keys.push(
                  match ValidatorSets::<T>::auxiliary_keys(validator, NetworkId::Serai) {
                    Some(serai_abi::primitives::crypto::EmbeddedEllipticCurveKeys::Serai(key)) => {
                      sp_core::sr25519::Public::from(key)
                    }
                    Some(_) => {
                      panic!(
                        "`ValidatorSets` yielded auxiliary key for XYZ despite requesting `Serai`"
                      )
                    }
                    None => {
                      panic!("validator missing auxiliary keys for network they were selected for")
                    }
                  },
                );
              }
            }

            // Check these iterators were of the same length
            if signature_participants.next().is_some() || selected_validators.next().is_some() {
              Err(InvalidTransaction::BadProof)?;
            }

            // Check a sufficient amount of validators signed these values
            let f = total_key_shares - participating_key_shares;
            if participating_key_shares < ((2 * f) + 1) {
              Err(InvalidTransaction::BadProof)?;
            }

            /*
              Verify the signature itself.

              Despite fetching the validators for the latest Serai session, which we assume is the
              genesis validators, we sign the signature as if the genesis session outright. This is
              due to the intent represented, where the fact we fetch the validators for the latest
              Serai session in order to fetch the genesis validators is solely an implementation
              detail.
            */
            let public_key: sp_core::sr25519::Public =
              (ValidatorSet { network: NetworkId::Serai, session: Session(0) })
                .musig_key(&participating_keys);
            if !public_key.verify(
              &values.oraclize_values_message(),
              &sp_core::sr25519::Signature::from(*signature),
            ) {
              Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof)?
            }
          }

          ValidTransaction::with_tag_prefix("GenesisLiquidity")
            .and_provides(())
            .longevity(KeyShares::MAX_PER_SET_U32.into())
            .propagate(true)
            .build()
        }
        Call::transfer_genesis_liquidity { .. } | Call::remove_genesis_liquidity { .. } => {
          Err(InvalidTransaction::Call)?
        }
        Call::__Ignore(_, _) => unreachable!(),
      }
    }

    // Explicitly provide a pre-dispatch which calls `validate_unsigned`
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ())
    }
  }
}

pub use pallet::{Config, Error, Pallet, Call};
#[doc(hidden)]
pub use pallet::*;
