#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

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
  use sp_application_crypto::RuntimePublic as _;

  use frame_support::{pallet_prelude::*, dispatch::RawOrigin};
  use frame_system::pallet_prelude::*;

  use serai_abi::{
    primitives::{prelude::*, crypto::Signature},
    in_instructions::Event,
  };

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;
  type LiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::LiquidityTokensInstance>;

  /// The weights for the pallet.
  pub trait Weights {
    /// The weight for a call to `execute_batch`.
    fn execute_batch() -> Weight;
  }

  /// A shimmed set of weights, returning zero.
  ///
  /// This is NOT safe for usage in a production system and is provided only for testing purposes.
  impl Weights for () {
    fn execute_batch() -> Weight {
      Weight::zero()
    }
  }

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_validator_sets_pallet::Config
    + serai_signals_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
    + serai_dex_pallet::Config
    + serai_economic_security_pallet::Config
    + serai_genesis_liquidity_pallet::Config
  {
    /// The weights for this pallet's calls.
    type Weights: Weights;
  }

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T> {
    /// A pre-Economic Security operation was attempted post-Economic Security.
    ///
    /// Note this may returned if a relevant _network_ has already achieved economic security, even
    /// if Serai as a whole is not considered within the post-Economic Security era.
    AlreadyAchievedEconomicSecurity,
    /// An amount was outsized ('unhealthy') in relation to the context.
    OutsizedAmount,
    /// A median which would have been used was unhealthy and not fit for use.
    UnhealthyMedian,
  }

  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  const BLOCKS_TO_ADD_PENDING_LIQUIDITY_OVER: u32 =
    (serai_abi::primitives::constants::WEEK.as_millis() /
      serai_abi::primitives::constants::TARGET_BLOCK_TIME.as_millis()) as u32;

  /// The total amount of pending liquidity for a coin.
  #[pallet::storage]
  type TotalPendingLiquidity<T: Config> = StorageMap<_, Identity, ExternalCoin, Amount, ValueQuery>;
  /// A view of pending liquidity, indexed by the block on which it was queued.
  #[pallet::storage]
  type PendingLiquidity<T: Config> =
    StorageDoubleMap<_, Identity, ExternalCoin, Identity, BlockNumberFor<T>, Amount, OptionQuery>;
  /// The amount of pending liqudity to add with each block.
  #[pallet::storage]
  type PendingLiquidityPerBlock<T: Config> =
    StorageMap<_, Identity, ExternalCoin, Amount, OptionQuery>;

  impl<T: Config> frame_support::traits::PreInherents for Pallet<T> {
    fn pre_inherents() {
      for coin in ExternalCoin::all() {
        let Some(mut pending_liquidity_per_block) = PendingLiquidityPerBlock::<T>::get(coin) else {
          continue;
        };

        if let Some(pending_liquidity_resolving_this_block) = {
          let historical_block = frame_system::Pallet::<T>::block_number()
            .checked_sub(&BlockNumberFor::<T>::from(BLOCKS_TO_ADD_PENDING_LIQUIDITY_OVER.max(1)));
          historical_block
            .and_then(|historical_block| PendingLiquidity::<T>::take(coin, historical_block))
        } {
          TotalPendingLiquidity::<T>::mutate(coin, |prior_total| {
            *prior_total = ((*prior_total) - pending_liquidity_resolving_this_block)
              .expect("more pending liquidity from this block than from all blocks");
          });

          let pending_liquidity_per_block_from_resolving = Amount(
            pending_liquidity_resolving_this_block
              .0
              .checked_div(u64::from(BLOCKS_TO_ADD_PENDING_LIQUIDITY_OVER))
              .unwrap_or(0),
          );

          // Because we have now (or will have at the end of this function) added this entire
          // amount, reduce the rate at which we add liquidity to the pools
          {
            let new_pending_liquidity_per_block = (pending_liquidity_per_block -
              pending_liquidity_per_block_from_resolving)
              .expect("more pending liquidity per block from this block than from all blocks");
            PendingLiquidityPerBlock::<T>::set(
              coin,
              Some(new_pending_liquidity_per_block).filter(|value| *value != Amount(0)),
            );
          }

          /*
            Add the difference between the total amount to add, and the amount already added with
            each block (which used a floordiv), to the amount to add with this final block.

            This multiplication is safe as the result is bounded to be
            `<= pending_liquidity_resolving_this_block` which fits within an `Amount`.
          */
          let resolving_pending_liquidity_added_per_block = Amount(
            pending_liquidity_per_block_from_resolving.0 *
              u64::from(BLOCKS_TO_ADD_PENDING_LIQUIDITY_OVER),
          );
          let remainder = (pending_liquidity_resolving_this_block -
            resolving_pending_liquidity_added_per_block)
            .expect("amounts added over time exceeded total");
          pending_liquidity_per_block = (pending_liquidity_per_block + remainder)
            .expect("pending liquidity exceed supply (bound to representable in `Amount`)");
        }

        // Actually add the coins to serve as liquidity
        Coins::<T>::transfer_fn(
          serai_abi::in_instructions::pending_liquidity_address(coin),
          serai_abi::dex::address(coin),
          Balance { coin: coin.into(), amount: pending_liquidity_per_block },
        )
        .expect(
          "expected pending liquidity for this block wasn't present in pending liquidity address",
        );
      }
    }
  }

  /// The block the last batch was published during.
  ///
  /// This is used to restrict publication of batches to once-per-block, limiting the impact of a
  /// compromised publisher from bloating the Serai blockchain with spam.
  #[pallet::storage]
  type BlockOfLastBatch<T: Config> =
    StorageMap<_, Identity, ExternalNetworkId, BlockNumberFor<T>, OptionQuery>;

  /// The ID of the last batch which was published.
  #[pallet::storage]
  type LastBatch<T: Config> = StorageMap<_, Identity, ExternalNetworkId, u32, OptionQuery>;

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    fn emit_event(event: Event) {
      Core::<T>::emit_event(event)
    }

    fn swap_to_staked_sri(
      in_instructions_address: SeraiAddress,
      external_balance_in: ExternalBalance,
      validator: SeraiAddress,
      network: NetworkId,
      minimum: Amount,
    ) -> Result<(), DispatchError> {
      // Check the network in question has yet to reach economic security
      if match network {
        NetworkId::Serai => ExternalNetworkId::all().all(<
          serai_economic_security_pallet::Pallet<T>
            as
           serai_abi::economic_security::EconomicSecurity
        >::achieved_economic_security),
        NetworkId::External(network) => {
        <
          serai_economic_security_pallet::Pallet<T>
            as
           serai_abi::economic_security::EconomicSecurity
        >::achieved_economic_security(network)
        }
      } {
        Err(Error::<T>::AlreadyAchievedEconomicSecurity)?;
      }

      /*
        Check this value isn't outsized (>50%) with regards to the pool.

        This limit can be seen as absurdly high. The reason it is what it is is because:
        1) This is premised on the healthy median
        2) For just `4` genesis validators, the allocation for a key share for a network will be
           approximate to 20% of the value in its pools, so this does actually have to support
           large percentages and handle them accordingly
      */
      let pool_address = serai_abi::dex::address(external_balance_in.coin);
      if {
        let pool_balance = Coins::<T>::balance(pool_address, external_balance_in.coin);
        // This encodes `(2 * external_balance_in.amount) <= pool_balance` without risk of
        // artihmetic under/overflows or traps
        Amount(pool_balance.0 / 2) < external_balance_in.amount
      } {
        Err(Error::<T>::OutsizedAmount)?;
      }

      /*
        Fetch the median quote, denoting the value of one unit of the coin in SRI.

        This also implicitly checks the pools were initialized and genesis has completed.
      */
      let Some(median_quote) =
        serai_economic_security_pallet::Pallet::<T>::healthy_median_quote(external_balance_in.coin)
      else {
        Err(Error::<T>::UnhealthyMedian)?
      };
      let median_quote = u64::try_from(median_quote).map_err(|_| Error::<T>::UnhealthyMedian)?;

      // Calculate the SRI value at the median quote
      let sri_value = (u128::from(external_balance_in.amount.0) * u128::from(median_quote)) /
        u128::from(10u64.pow(external_balance_in.coin.decimals()));
      let sri_value =
        Amount(u64::try_from(sri_value).map_err(|_| serai_dex_pallet::Error::<T>::Overflow)?);
      if sri_value < minimum {
        Err(serai_dex_pallet::Error::<T>::Unsatisfied)?;
      }

      /*
        Due to the lack of `allocate_to`, and practical indifference, here we mint directly to the
        specified address and perform the allocate call as if they had made such a transaction.
        This does create the interesting scenario where an address with no intent to be considered
        a validator could have a third-party allocate to their address (the address in question
        then controlling the stake due to the lack of delegated Proof of Stake) to force them into
        that position. Since allocating requires first registering keys, which can be seen as
        explicit intent, we do not consider this a concern.
      */
      Coins::<T>::mint(validator, Balance { coin: Coin::Serai, amount: sri_value })?;
      serai_validator_sets_pallet::Pallet::<T>::allocate(
        Some(validator).into(),
        network,
        sri_value,
      )?;

      /*
        Check this isn't allocating past the amount required for economic security.

        This may appear to make the first check we performed, that the network has yet to reach
        economic security, redundant. The first check is immediate and clear however, while this
        has a bit more math to it. Additionally, this check may pass if a network has achieved
        economic security _but is not currently considered economically secure_, which is why the
        explicit check at the start is necessary. This functionality is not expected to re-enable
        itself under such a situation.

        The methodology of this implementation also uses `total_allocated_stake_for_network` which
        is only really sane during the pre-Economic Security era, when all validators can be
        assumed as will be selected and validators are unable to deallocate stake.
      */
      {
        let stake =
          serai_validator_sets_pallet::Pallet::<T>::total_allocated_stake_for_network(network);
        /*
          This uses `liquidity_stake_requirement as `coins_stake_requirement` will be 'wrong'. It
          will be inflated by the minting of coins used here for this swap to staked SRI, but as
          these coins are added to the liquidity pool _without_ additional SRI, the quote will
          lower such that the original product of the coins, quote is equal to the new product of
          the coins, quote. This just takes time for the quote (and associated median) to actually
          be reduced.

          This policy does handwave the potential economic security requirement for coins outside
          of the liquidity pool, which is deemed acceptable here as those are always intended to be
          relatively minor and already face a relaxed definition of economic security. In the worst
          case, finally achieving economic security would not be possible via this mechanism
          (due to it prematurely disabling itself) yet solely the traditional method of allocating.
        */
        let required_stake = match network {
          NetworkId::Serai => {
            let external_stake_required = ExternalNetworkId::all()
              .map(
                serai_validator_sets_pallet::liquidity_stake_requirement::<
                  T,
                  serai_economic_security_pallet::Pallet<T>,
                >,
              )
              .fold(Amount(0), |accum, requirement| Amount(accum.0.saturating_add(requirement.0)));
            // This inlines a formula derived from `SERAI_VALIDATORS_DESIRED_PERCENTAGE`
            Amount(external_stake_required.0 / 4)
          }
          NetworkId::External(network) => {
            serai_validator_sets_pallet::liquidity_stake_requirement::<
              T,
              serai_economic_security_pallet::Pallet<T>,
            >(network)
          }
        };
        let allocation_per_key_share =
          serai_validator_sets_pallet::Pallet::<T>::allocation_per_key_share(network)
            .expect("pools were initialized but `allocation_per_key_share` not set");
        if stake >= Amount(required_stake.0.saturating_add(allocation_per_key_share.0)) {
          /*
            This slightly overloads this error as we have not actually done this yet, but it's a
            reasonable assumption this will occur _and_ slightly overloading this isn't a real
            concern.
          */
          Err(Error::<T>::AlreadyAchievedEconomicSecurity)?;
        }
      }

      /*
        Form Protocol-owned Liqudity out of the external balance, which is done in two steps:

        1) Update the amount of liquidity tokens corresponding to genesis liquidity to represent
           the same amount of the external coin _after this external balance is added_. While this
           _temporarily_ reduces the amount of the external coin available for removals of genesis
           liquidity, the genesis liquidity module is designed to comprehensively handle such cases
           _and_ this amount will be still be introduced into the pool later, making this situation
           emphemeral.

        2) Trickle-feed the external coin into the pool to prevent 'clipping' what may be up to 50%
           of the pool depth into the pool within a single block.

        The following block implements the first step.
      */
      {
        let genesis_liquidity_address =
          serai_abi::genesis_liquidity::address(external_balance_in.coin);
        let genesis_liquidity_liquidity_tokens =
          LiquidityTokens::<T>::balance(genesis_liquidity_address, external_balance_in.coin);
        let total_liquidity_tokens = LiquidityTokens::<T>::supply(external_balance_in.coin);

        let pool_external = Coins::<T>::balance(pool_address, external_balance_in.coin);
        /*
          We consider the pool's balance not just as its literal balance, but its literal balance
          plus the coins we have pending. This is because some genesis liquidity tokens may have
          already been converted to protocol-owned liquidity with the expectation being the
          remaining gensis liquidity will resolve as corresponding to the same effective amount of
          the external coins. If we were to further decrease the amount of genesis liquidity tokens
          now however, without such consideration, the genesis liquidity tokens would correspond to
          a lesser share of the pending liquidity and receive less than intended.
        */
        let pool_external = (pool_external +
          TotalPendingLiquidity::<T>::get(external_balance_in.coin))
        .expect(
          "expected pool external balance exceeded supply (bound to be representable in `Amount`)",
        );
        let pool_external_after = (pool_external + external_balance_in.amount)
          .expect("pool external balance exceeded supply (bound to be representable in `Amount`)");

        let genesis_liquidity_external = (u128::from(pool_external.0) *
          u128::from(genesis_liquidity_liquidity_tokens.0)) /
          u128::from(total_liquidity_tokens.0);
        // dividend was `u64`, divisor was `<= 1`, quotient will be `u64`
        let genesis_liquidity_external = Amount(u64::try_from(genesis_liquidity_external).unwrap());
        let genesis_liquidity_external_after = (u128::from(pool_external_after.0) *
          u128::from(genesis_liquidity_liquidity_tokens.0)) /
          u128::from(total_liquidity_tokens.0);
        let genesis_liquidity_external_after =
          Amount(u64::try_from(genesis_liquidity_external_after).unwrap());

        /*
          We want to convert `1 - (genesis_liquidity_external / genesis_liquidity_external_after)`
          of the genesis liquidity into protocol-owned liqudity such that the remaining liquidity
          tokens, after the pool receives these coins, correspond to the same amount of the
          external coin.

          We calculate this as calculating how many of the liquidity tokens should _remain_ in
          genesis liquidity, converting the difference into protocol-owned liquidity. The following
          usage of a `div_ceil` ensures the genesis liquidity module is _favored_ and we do not
          convert any more into protocol-owned liquidity than we have outright claim to.

          We know this won't trap as the pool must have liquidity as it has been initialized.
        */
        let genesis_liquidity_liquidity_tokens_after =
          (u128::from(genesis_liquidity_liquidity_tokens.0) *
            u128::from(genesis_liquidity_external.0))
          .div_ceil(u128::from(genesis_liquidity_external_after.0));
        let genesis_liquidity_liquidity_tokens_after =
          Amount(u64::try_from(genesis_liquidity_liquidity_tokens_after).unwrap());
        // Because the amount of external coin increased, the liquidity tokens corresponding to
        // this fixed amount would have decreased
        let new_protocol_owned_liquidity =
          (genesis_liquidity_liquidity_tokens - genesis_liquidity_liquidity_tokens_after).unwrap();
        // The pool's address is used to represent the holder of protocol-owned liquidity
        serai_dex_pallet::Pallet::<T>::transfer_liquidity(
          Some(genesis_liquidity_address).into(),
          serai_abi::dex::address(external_balance_in.coin),
          ExternalBalance { coin: external_balance_in.coin, amount: new_protocol_owned_liquidity },
        )?;
      }

      // Now, queue the coins to be added into the pool over the specified amount of time
      {
        Coins::<T>::transfer_fn(
          in_instructions_address,
          serai_abi::in_instructions::pending_liquidity_address(external_balance_in.coin),
          external_balance_in.into(),
        )?;

        TotalPendingLiquidity::<T>::mutate(external_balance_in.coin, |existing_total| {
          *existing_total = ((*existing_total) + external_balance_in.amount).expect(
            "total pending liquidity exceeded supply (bound to be representable in `Amount`)",
          );
        });
        PendingLiquidity::<T>::mutate(
          external_balance_in.coin,
          frame_system::Pallet::<T>::block_number(),
          |pending_liquidity| {
            *pending_liquidity = Some((
              (*pending_liquidity).unwrap_or(Amount(0)) + external_balance_in.amount
            ).expect(
              "pending liquidity from block exceeded supply (bound to be representable in `Amount`)"
            ));
          },
        );
        PendingLiquidityPerBlock::<T>::mutate(
          external_balance_in.coin,
          |pending_liquidity_per_block| {
            let existing = (*pending_liquidity_per_block).unwrap_or(Amount(0));
            // This uses a floor division where on the last block, the remainder is expected to be
            // handled by whatever code actually adds this pending liquidity to the liquidity pool
            *pending_liquidity_per_block = Some((
              existing +
              Amount(external_balance_in
                .amount
                .0
                .checked_div(u64::from(BLOCKS_TO_ADD_PENDING_LIQUIDITY_OVER))
                .unwrap_or(0)))
            .expect(
              "pending liquidity per block exceeded supply (bound to be representable in `Amount`)",
            ));
          },
        );
      }

      Ok(())
    }

    /// Execute an `InInstructionWithBalance`.
    ///
    /// We execute this within a database layer to ensure it's atomic, executing entirely or not at
    /// all.
    #[frame_support::transactional]
    fn execute(instruction: InInstructionWithBalance) -> DispatchResult {
      let InInstructionWithBalance { instruction, balance: external_balance_in } = instruction;
      let external_coin = external_balance_in.coin;

      /*
        Mint the balance to ourself.

        We use a consistent address to represent `InInstruction`s as we do need some address for
        all the operations present here, unable to directly pipe through a composition of all
        desired effects, and use usage of `InInstructions` (not the recipient's address) ensures a
        degree of isolation with the operations here. Specifically, if this did behave on behalf of
        a user (using their address), and a bad segment of code attempted to transfer more than
        provided via the `InInstruction`, that would return an error here but otherwise work if the
        user already had the additionally required balance. It also prevents anyone who makes an
        `InInstruction` from performing actions on behalf of a user, even if said actions solely
        increase the user's balance.

        This does mean coins may be left here however if the following operations don't ensure
        they're transferred out by the end of the call. That alone isn't considered a bug, so long
        as the user's intent is satisfied, and dust is fine to leave behind. The following calls
        SHOULD leave the account without any balance however.
      */
      let in_instructions_address = serai_abi::in_instructions::address();
      Coins::<T>::mint(in_instructions_address, external_balance_in.into())?;

      match instruction {
        InInstruction::GenesisLiquidity(to) => {
          serai_genesis_liquidity_pallet::Pallet::<T>::add_liquidity(
            in_instructions_address,
            to,
            external_balance_in,
          )?;
        }
        InInstruction::SwapToStakedSri { validator, network, minimum } => {
          Self::swap_to_staked_sri(
            in_instructions_address,
            external_balance_in,
            validator,
            network,
            minimum,
          )?;
        }
        InInstruction::TransferWithSwap { to, maximum_to_swap, sri } => {
          serai_dex_pallet::Pallet::<T>::swap_for(
            RawOrigin::Signed(in_instructions_address).into(),
            Balance { coin: Coin::Serai, amount: sri },
            Balance { coin: external_coin.into(), amount: maximum_to_swap },
          )?;

          for coin in [Coin::Serai, external_coin.into()] {
            Coins::<T>::transfer_fn(
              in_instructions_address,
              to,
              Balance { coin, amount: Coins::<T>::balance(in_instructions_address, coin) },
            )?;
          }
        }
        InInstruction::Transfer { to } => {
          // This could have been minted directly to the user if we didn't want to insist on using
          // the `InInstruction`s' address for isolation and provenance
          Coins::<T>::transfer_fn(in_instructions_address, to, external_balance_in.into())?;
        }
        InInstruction::SwapAndAddLiquidity {
          address: destination,
          external_coin_liquidity,
          sri_minimum,
          sri_for_fees,
        } => {
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(in_instructions_address).into(),
            Balance {
              coin: external_coin.into(),
              amount: (external_balance_in.amount - external_coin_liquidity)
                .ok_or(serai_dex_pallet::Error::<T>::Underflow)?,
            },
            Balance {
              coin: Coin::Serai,
              amount: (sri_minimum + sri_for_fees).ok_or(serai_dex_pallet::Error::<T>::Overflow)?,
            },
          )?;

          let sri_intended =
            (Coins::<T>::balance(in_instructions_address, Coin::Serai) - sri_for_fees).expect(
              "swapped to amount sufficient for minimum, fees, but received less than for fees?",
            );
          let external_coin_intended = external_coin_liquidity;
          let external_coin_minimum = external_coin_liquidity;
          serai_dex_pallet::Pallet::<T>::add_liquidity(
            RawOrigin::Signed(in_instructions_address).into(),
            external_coin,
            sri_intended,
            external_coin_intended,
            sri_minimum,
            external_coin_minimum,
          )?;

          /*
            Transfer the rest, which will be greater than or equal to the amount requested for
            fees, to the destination.

            While this only transfers `Coin::Serai`, there should not be any leftover
            `Coin::External(_)` due to adding an amount such that
            `external_coin_intended <= amount <= external_coin_intended` where
            `external_coin_intended = external_coin_intended` and swapping
            `balance.amount - external_coin_intended` to SRI.
          */
          Coins::<T>::transfer_fn(
            in_instructions_address,
            destination,
            Balance {
              coin: Coin::Serai,
              amount: Coins::<T>::balance(in_instructions_address, Coin::Serai),
            },
          )?;
        }
        InInstruction::Swap { address: destination, minimum_to_receive } => {
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(in_instructions_address).into(),
            external_balance_in.into(),
            minimum_to_receive,
          )?;

          let coin = minimum_to_receive.coin;
          let received_amount = Coins::<T>::balance(in_instructions_address, coin);
          let received = Balance { coin, amount: received_amount };
          Coins::<T>::transfer_fn(in_instructions_address, destination, received)?;
        }
        InInstruction::SwapOut { instruction, minimum_to_receive } => {
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(in_instructions_address).into(),
            external_balance_in.into(),
            minimum_to_receive.into(),
          )?;

          let coin = minimum_to_receive.coin;
          let received_amount = Coins::<T>::balance(in_instructions_address, Coin::from(coin));
          let received = ExternalBalance { coin, amount: received_amount };
          // This is disallowed as this must only be called with `CoinsInstance`, which this does
          #[expect(clippy::disallowed_methods)]
          Coins::<T>::burn_with_instruction(
            RawOrigin::Signed(in_instructions_address).into(),
            OutInstructionWithBalance { instruction, balance: received },
          )?;
        }
      }

      Ok(())
    }
  }

  #[derive(Clone, Copy, Encode, Decode, MaxEncodedLen)]
  enum SignedBySession {
    Current,
    LatestDecided,
  }

  /// The `SignedBySession` value for the batch currently being executed.
  ///
  /// We need to propagate the context of `signed_by_session` (from `validate_execute_batch`) to
  /// `execute_batch`. As the API of `pre_dispatch` does not allow us to associate context, we use
  /// this dedicated storage slot. It should never appear in any state root as it should only live
  /// between when `pre_dispatch` is called and the immediately following dispatch.
  #[pallet::storage]
  type SignedBySessionStorage<T: Config> = StorageValue<_, SignedBySession, OptionQuery>;

  impl<T: Config> Pallet<T> {
    /// Validate a call to `validate_execute_batch`.
    ///
    /// This function will solely read from the existing storage and will not perform any storage
    /// updates.
    fn validate_execute_batch(batch: &SignedBatch) -> Result<SignedBySession, InvalidTransaction> {
      let network = batch.batch.network();

      // Verify the network isn't halted
      if serai_signals_pallet::Pallet::<T>::halted(network) {
        Err(InvalidTransaction::Custom(0))?;
      }

      // Verify the `Batch`'s signature
      let signed_by_session = {
        let message = batch.batch.publish_batch_message();

        // If this message was signed by the specified session.
        let signed_by_session = |session| {
          let Some(key) =
            serai_validator_sets_pallet::Pallet::<T>::oraclization_key(ExternalValidatorSet {
              network,
              session,
            })
          else {
            // If this session has not set its oraclization key, it cannot be the signer.
            return false;
          };
          match batch.signature {
            Signature::Ristretto(signature) => key.verify(&message, &signature.into()),
          }
        };

        // Check if this was signed by the current session, as likely.
        if {
          let Some(current_session) =
            serai_validator_sets_pallet::Pallet::<T>::current_session(network.into())
          else {
            Err(InvalidTransaction::BadProof)?
          };
          signed_by_session(current_session)
        } {
          SignedBySession::Current
        } else {
          // If it wasn't signed by the current session, check if the latest decided session did
          let latest_decided_session =
            serai_validator_sets_pallet::Pallet::<T>::latest_decided_session(network.into())
              .expect("current session yet never one decided?");
          if !signed_by_session(latest_decided_session) {
            // Since neither the current not latest decided session this, the signer is invalid
            Err(InvalidTransaction::BadProof)?;
          }
          SignedBySession::LatestDecided
        }
      };

      // Verify every balance in the `Batch` is for a coin associated with this network
      for instruction in batch.batch.instructions() {
        if instruction.balance.coin.network() != network {
          Err(InvalidTransaction::Custom(1))?;
        }
      }

      // Verify this is the only `Batch` for this block
      let current_block_number = frame_system::Pallet::<T>::block_number();
      if BlockOfLastBatch::<T>::get(network) == Some(current_block_number) {
        // This transaction is valid in the future, the next block, but not now
        Err(InvalidTransaction::Future)?;
      }

      // Verify this `Batch` descends immediately from the prior `Batch`
      let required_last_batch = batch.batch.id().checked_sub(1);
      {
        let last_batch = LastBatch::<T>::get(network);
        if last_batch < required_last_batch {
          Err(InvalidTransaction::Future)?;
        }
        if last_batch > required_last_batch {
          Err(InvalidTransaction::Stale)?;
        }
      }

      Ok(signed_by_session)
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Execute a batch of `InInstruction`s.
    #[pallet::call_index(0)]
    #[pallet::weight((<T as Config>::Weights::execute_batch(), DispatchClass::Normal))]
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      let batch = batch.batch;
      let network = batch.network();

      BlockOfLastBatch::<T>::set(network, Some(frame_system::Pallet::<T>::block_number()));
      LastBatch::<T>::set(network, Some(batch.id()));

      /*
        Not only does this `expect` ensure `pre_dispatch` (and therefore `validate_execute_batch`)
        was called, as required for the safety of this, the usage of a singular storage slot
        ensures we _cannot_ have `[SignedBySession::LatestDecided, SignedBySession::LatestDecided]`
        populated (where the second instance would have its value invalidated by this following
        block).
      */
      match SignedBySessionStorage::<T>::take()
        .expect("executing `Batch` without context from `pre_dispatch`?")
      {
        SignedBySession::Current => {}
        /*
          Because the latest decided session, which is not the current session, has taken over for
          publishing `Batch`es, it has agreed to become the current session.
        */
        SignedBySession::LatestDecided => {
          serai_validator_sets_pallet::Pallet::<T>::accept_handover(network)
        }
      }

      // Execute all of the contained instructions, premised on how `execute` is transactional
      let mut in_instruction_results = bitvec::vec::BitVec::new();
      for instruction in batch.instructions() {
        in_instruction_results.push(Self::execute(instruction.clone()).is_ok());
      }

      // The publishing session is always the current session, as if it wasn't, it would be
      // considered to have accepted its handover and would have now become the current session
      let publishing_session =
        serai_validator_sets_pallet::Pallet::<T>::current_session(network.into())
          .expect("`SignedBatch` for a network without a session was validated");

      Self::emit_event(Event::Batch {
        network,
        publishing_session,
        id: batch.id(),
        external_network_block_hash: batch.external_network_block_hash(),
        in_instructions_hash: sp_core::blake2_256(&borsh::to_vec(batch.instructions()).unwrap()),
        in_instruction_results: in_instruction_results
          .try_into()
          .expect("`Batch` had more instructions than allowed results"),
      });

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      let batch = match call {
        Call::execute_batch { batch } => batch,
        Call::__Ignore(_, _) => Err(InvalidTransaction::Call)?,
      };
      let _signed_by_session = Self::validate_execute_batch(batch)?;

      let mut builder = ValidTransaction::with_tag_prefix("InInstructions");
      if let Some(required_last_batch) = batch.batch.id().checked_sub(1) {
        builder = builder.and_requires((batch.batch.network(), required_last_batch));
      }
      builder
        .and_provides((batch.batch.network(), batch.batch.id()))
        .longevity(serai_abi::primitives::validator_sets::KeyShares::MAX_PER_SET_U64)
        .propagate(true)
        .build()
    }

    /// Explicitly provide a `pre_dispatch` which calls `validate_unsigned`.
    ///
    /// This is reasonably assumed, and the current provided implementation, but not guaranteed by
    /// the documentation.
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      let batch = match call {
        Call::execute_batch { batch } => batch,
        Call::__Ignore(_, _) => Err(InvalidTransaction::Call)?,
      };
      let signed_by_session = Self::validate_execute_batch(batch)?;

      /*
        We explicitly check it isn't already set to ensure we never simultaneously store two
        values. This `assert` should be fine as such a scenario would only happen if `pre_dispatch`
        was called for _multiple unsigned calls_ before they were actually dispatched, which the
        Serai transaction format does not allow
      */
      assert!(!SignedBySessionStorage::<T>::exists());
      SignedBySessionStorage::<T>::set(Some(signed_by_session));
      Ok(())
    }
  }
}

pub use pallet::{Weights, Config, Error, Pallet, Call};
#[doc(hidden)]
pub use pallet::*;
