#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::{pallet_prelude::*, RawOrigin};
  use frame_support::{
    pallet_prelude::*,
    sp_runtime::{self, SaturatedConversion},
  };

  use sp_std::{vec, vec::Vec, collections::btree_map::BTreeMap};
  use sp_core::sr25519::Signature;
  use sp_application_crypto::RuntimePublic;

  use dex_pallet::{Pallet as Dex, Config as DexConfig};
  use coins_pallet::{Config as CoinsConfig, Pallet as Coins, AllowMint};

  use serai_primitives::*;
  use validator_sets_primitives::{ValidatorSet, Session, musig_key};
  pub use genesis_liquidity_primitives as primitives;
  use primitives::*;

  /// LiquidityTokens Pallet as an instance of coins pallet.
  pub type LiquidityTokens<T> = coins_pallet::Pallet<T, coins_pallet::Instance1>;

  #[pallet::config]
  pub trait Config:
    frame_system::Config + DexConfig + CoinsConfig + coins_pallet::Config<coins_pallet::Instance1>
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<T::AccountId>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { participants: Default::default() }
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    GenesisPeriodEnded,
    AmountOverflowed,
    NotEnoughLiquidity,
    CanOnlyRemoveFullAmount,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    GenesisLiquidityAdded { by: SeraiAddress, balance: Balance },
    GenesisLiquidityRemoved { by: SeraiAddress, balance: Balance },
    GenesisLiquidityAddedToPool { coin1: Balance, coin2: Balance },
    EconomicSecurityReached { network: NetworkId },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  pub(crate) type Liquidity<T: Config> =
    StorageDoubleMap<_, Identity, Coin, Blake2_128Concat, PublicKey, SubstrateAmount, OptionQuery>;

  #[pallet::storage]
  pub(crate) type LiquidityTokensPerAddress<T: Config> =
    StorageDoubleMap<_, Identity, Coin, Blake2_128Concat, PublicKey, SubstrateAmount, OptionQuery>;

  #[pallet::storage]
  pub(crate) type EconomicSecurityReached<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, ValueQuery>;

  #[pallet::storage]
  pub(crate) type Participants<T: Config> =
    StorageMap<_, Identity, NetworkId, BoundedVec<PublicKey, ConstU32<150>>, ValueQuery>;

  #[pallet::storage]
  pub(crate) type Oracle<T: Config> = StorageMap<_, Identity, Coin, u64, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      Participants::<T>::set(NetworkId::Serai, self.participants.clone().try_into().unwrap());
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(n: BlockNumberFor<T>) {
      // Distribute the genesis sri to pools after a month
      if n == GENESIS_PERIOD_BLOCKS.into() {
        // mint the SRI
        Coins::<T>::mint(
          GENESIS_LIQUIDITY_ACCOUNT.into(),
          Balance { coin: Coin::Serai, amount: Amount(GENESIS_SRI) },
        )
        .unwrap();

        // get coin values & total
        let mut account_values = BTreeMap::new();
        let mut pool_values = vec![];
        let mut total_value: u128 = 0;
        for coin in COINS {
          if coin == Coin::Serai {
            continue;
          }

          // initial coin value in terms of btc
          let value = Oracle::<T>::get(coin);

          // get the pool & individual address values
          account_values.insert(coin, vec![]);
          let mut pool_amount: u128 = 0;
          for (account, amount) in Liquidity::<T>::iter_prefix(coin) {
            pool_amount = pool_amount.saturating_add(amount.into());
            let value_this_addr =
              u128::from(amount).saturating_mul(value.into()) / 10u128.pow(coin.decimals());
            account_values.get_mut(&coin).unwrap().push((account, value_this_addr))
          }
          // sort, so that everyone has a consistent accounts vector per coin
          account_values.get_mut(&coin).unwrap().sort();

          let pool_value = pool_amount.saturating_mul(value.into()) / 10u128.pow(coin.decimals());
          total_value = total_value.saturating_add(pool_value);
          pool_values.push((coin, pool_amount, pool_value));
        }

        // add the liquidity per pool
        let mut total_sri_distributed = 0;
        let pool_values_len = pool_values.len();
        for (i, (coin, pool_amount, pool_value)) in pool_values.into_iter().enumerate() {
          // whatever sri left for the last coin should be ~= it's ratio
          let sri_amount = if i == (pool_values_len - 1) {
            GENESIS_SRI - total_sri_distributed
          } else {
            u64::try_from(u128::from(GENESIS_SRI).saturating_mul(pool_value) / total_value).unwrap()
          };
          total_sri_distributed += sri_amount;

          // we can't add 0 liquidity
          if !(pool_amount > 0 && sri_amount > 0) {
            continue;
          }

          // actually add the liquidity to dex
          let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
          Dex::<T>::add_liquidity(
            origin.into(),
            coin,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            GENESIS_LIQUIDITY_ACCOUNT.into(),
          )
          .unwrap();

          // let everyone know about the event
          Self::deposit_event(Event::GenesisLiquidityAddedToPool {
            coin1: Balance { coin, amount: Amount(u64::try_from(pool_amount).unwrap()) },
            coin2: Balance { coin: Coin::Serai, amount: Amount(sri_amount) },
          });

          // set liquidity tokens per account
          let tokens =
            u128::from(LiquidityTokens::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin).0);
          let mut total_tokens_this_coin: u128 = 0;

          let accounts = account_values.get(&coin).unwrap();
          for (i, (acc, acc_value)) in accounts.iter().enumerate() {
            // give whatever left to the last account not to have rounding errors.
            let liq_tokens_this_acc = if i == accounts.len() - 1 {
              tokens - total_tokens_this_coin
            } else {
              tokens.saturating_mul(*acc_value) / pool_value
            };

            total_tokens_this_coin = total_tokens_this_coin.saturating_add(liq_tokens_this_acc);

            LiquidityTokensPerAddress::<T>::set(
              coin,
              acc,
              Some(u64::try_from(liq_tokens_this_acc).unwrap()),
            );
          }
          assert_eq!(tokens, total_tokens_this_coin);
        }
        assert_eq!(total_sri_distributed, GENESIS_SRI);

        // we shouldn't have left any coin in genesis account at this moment, including SRI.
        // All transferred to the pools.
        for coin in COINS {
          assert_eq!(Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin), Amount(0));
        }
      }

      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let existing = EconomicSecurityReached::<T>::get(coin.network());
        if existing == 0u32.into() &&
          <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityReached::<T>::set(coin.network(), n);
          Self::deposit_event(Event::EconomicSecurityReached { network: coin.network() });
        }
      }
    }
  }

  impl<T: Config> Pallet<T> {
    /// Add genesis liquidity for the given account. All accounts that provide liquidity
    /// will receive the genesis SRI according to their liquidity ratio.
    pub fn add_coin_liquidity(account: PublicKey, balance: Balance) -> DispatchResult {
      // check we are still in genesis period
      if Self::genesis_ended() {
        Err(Error::<T>::GenesisPeriodEnded)?;
      }

      // mint the coins
      Coins::<T>::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), balance)?;

      // save
      let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
      let new = existing.checked_add(balance.amount.0).ok_or(Error::<T>::AmountOverflowed)?;
      Liquidity::<T>::set(balance.coin, account, Some(new));

      Self::deposit_event(Event::GenesisLiquidityAdded { by: account.into(), balance });
      Ok(())
    }

    /// Returns the number of blocks since the coin's network reached economic security first time.
    /// If the network is yet to be reached that threshold, 0 is returned. And maximum of
    /// `GENESIS_SRI_TRICKLE_FEED` returned.
    fn blocks_since_ec_security(coin: &Coin) -> u64 {
      let ec_security_block =
        EconomicSecurityReached::<T>::get(coin.network()).saturated_into::<u64>();
      let current = <frame_system::Pallet<T>>::block_number().saturated_into::<u64>();
      if ec_security_block > 0 {
        let diff = current - ec_security_block;
        if diff > GENESIS_SRI_TRICKLE_FEED {
          return GENESIS_SRI_TRICKLE_FEED;
        }

        return diff;
      }

      0
    }

    fn genesis_ended() -> bool {
      <frame_system::Pallet<T>>::block_number() >= GENESIS_PERIOD_BLOCKS.into()
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Remove the provided genesis liquidity for an account.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn remove_coin_liquidity(origin: OriginFor<T>, balance: Balance) -> DispatchResult {
      let account = ensure_signed(origin)?;
      let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());

      // check we are still in genesis period
      if Self::genesis_ended() {
        // check user have enough to remove
        let existing = LiquidityTokensPerAddress::<T>::get(balance.coin, account).unwrap_or(0);
        if balance.amount.0 > existing {
          Err(Error::<T>::NotEnoughLiquidity)?;
        }

        // remove liquidity from pool
        let prev_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let prev_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);
        Dex::<T>::remove_liquidity(
          origin.clone().into(),
          balance.coin,
          balance.amount.0,
          1,
          1,
          GENESIS_LIQUIDITY_ACCOUNT.into(),
        )?;
        let current_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let current_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);

        // burn the SRI if necessary
        let mut sri = current_sri.0.saturating_sub(prev_sri.0);
        let distance_to_full_pay =
          GENESIS_SRI_TRICKLE_FEED - Self::blocks_since_ec_security(&balance.coin);
        let burn_sri_amount = sri.saturating_mul(distance_to_full_pay) / GENESIS_SRI_TRICKLE_FEED;
        Coins::<T>::burn(
          origin.clone().into(),
          Balance { coin: Coin::Serai, amount: Amount(burn_sri_amount) },
        )?;
        sri -= burn_sri_amount;

        // transfer to owner
        let coin_out = current_coin.0 - prev_coin.0;
        Coins::<T>::transfer(
          origin.clone().into(),
          account,
          Balance { coin: balance.coin, amount: Amount(coin_out) },
        )?;
        Coins::<T>::transfer(
          origin.into(),
          account,
          Balance { coin: Coin::Serai, amount: Amount(sri) },
        )?;

        // save
        let existing = LiquidityTokensPerAddress::<T>::get(balance.coin, account).unwrap_or(0);
        let new = existing.checked_sub(balance.amount.0).ok_or(Error::<T>::AmountOverflowed)?;
        LiquidityTokensPerAddress::<T>::set(balance.coin, account, Some(new));
      } else {
        let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
        if balance.amount.0 > existing || balance.amount.0 == 0 {
          Err(Error::<T>::NotEnoughLiquidity)?;
        }
        if balance.amount.0 < existing {
          Err(Error::<T>::CanOnlyRemoveFullAmount)?;
        }

        // TODO: do external transfer instead for making it easier for the user?
        // or do we even want to make it easier?
        Coins::<T>::transfer(origin.into(), account, balance)?;

        // save
        Liquidity::<T>::set(balance.coin, account, None);
      }

      Self::deposit_event(Event::GenesisLiquidityRemoved { by: account.into(), balance });
      Ok(())
    }

    /// A call to submit the initial coi values.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn set_initial_price(
      origin: OriginFor<T>,
      prices: Prices,
      _signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // set the prices
      Oracle::<T>::set(Coin::Bitcoin, prices.bitcoin);
      Oracle::<T>::set(Coin::Monero, prices.monero);
      Oracle::<T>::set(Coin::Ether, prices.ethereum);
      Oracle::<T>::set(Coin::Dai, prices.dai);
      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      match call {
        Call::set_initial_price { ref prices, ref signature } => {
          let set = ValidatorSet { network: NetworkId::Serai, session: Session(0) };
          let signers = Participants::<T>::get(NetworkId::Serai);

          if !musig_key(set, &signers).verify(&set_initial_price_message(&set, prices), signature) {
            Err(InvalidTransaction::BadProof)?;
          }

          ValidTransaction::with_tag_prefix("GenesisLiquidity")
            .and_provides((0, set))
            .longevity(u64::MAX)
            .propagate(true)
            .build()
        }
        Call::remove_coin_liquidity { .. } => Err(InvalidTransaction::Call)?,
        Call::__Ignore(_, _) => unreachable!(),
      }
    }
  }
}

pub use pallet::*;
