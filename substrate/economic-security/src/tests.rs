#![expect(clippy::as_conversions, clippy::same_name_method)]

use rand_core::{RngCore as _, OsRng};

use frame_support::{weights::Weight, traits::Hooks as _, derive_impl, construct_runtime};

use serai_abi::{
  primitives::{network_id::*, coin::*, balance::*, address::*},
  TransactionContext as _,
  economic_security::EconomicSecurity as _,
};

use serai_coins_pallet::{self as coins, CoinsInstance, LiquidityTokensInstance};

use crate as economic_security;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
    LiquidityTokens: coins::<LiquidityTokensInstance>,
    Dex: serai_dex_pallet,
    EconomicSecurity: economic_security,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = SeraiAddress;
  type Lookup = frame_support::sp_runtime::traits::IdentityLookup<Self::AccountId>;
  type Block = frame_system::mocking::MockBlock<Test>;
  type BlockLength = serai_core_pallet::Limits;
  type BlockWeights = serai_core_pallet::Limits;
}

impl From<serai_abi::Call> for RuntimeCall {
  fn from(_call: serai_abi::Call) -> Self {
    unimplemented!();
  }
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

impl serai_core_pallet::Config for Test {
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

pub struct NeverHalted;
impl serai_abi::signals::Halted for NeverHalted {
  fn halted(_network: ExternalNetworkId) -> bool {
    false
  }
}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = crate::CoinsInstanceAllowMint<Self>;
  type AllowBurnWithInstruction = NeverHalted;
  type Weights = ();
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Test {
  type AllowMint = crate::LiquidityTokensInstanceAllowMint<Self>;
  type AllowBurnWithInstruction = NeverHalted;
  type Weights = ();
}

impl serai_dex_pallet::Config for Test {
  type AllowSwap = NeverHalted;
  type Weights = ();
}

#[expect(unused)]
impl crate::ValidatorSets for () {
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Some(Amount(1))
  }
  fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
    Some(Amount(1))
  }
  fn coins_stake_requirement(
    network: ExternalNetworkId,
    proposed_additional_balance: Option<Balance>,
  ) -> Amount {
    Amount(1)
  }
  fn liquidity_stake_requirement(network: ExternalNetworkId) -> Amount {
    Amount(1)
  }
  fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
    Amount(1)
  }
}

impl crate::Config for Test {
  type ValidatorSets = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let system = frame_system::GenesisConfig::<Test>::default();
    let coins = serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let liquidity_tokens = serai_coins_pallet::GenesisConfig::<Test, LiquidityTokensInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let dex = serai_dex_pallet::GenesisConfig::<Test> {
      fees: ExternalCoin::all().map(|coin| (coin, 0)).collect(),
      _config: Default::default(),
    };
    Core::genesis(&RuntimeGenesisConfig { system, coins, liquidity_tokens, dex });
  });
  externalities
}

#[test]
fn historical_values() {
  use rand_core::{RngCore as _, OsRng};
  use substrate_median::LexicographicEncoding as _;

  new_test_ext().execute_with(|| {
    let key = ExternalCoin::Bitcoin;
    let mut values = vec![];
    let mut time = 0;
    for _ in 0 .. 16_384 {
      time += 1;

      const AGE_LIMIT: u64 = 512;
      // Use `PROBABILITY` to model missed slots
      const PROBABILITY: u64 = 2;
      const BOUND: usize = 4;
      if (OsRng.next_u64() % PROBABILITY) == 0 {
        let value = u128::from(OsRng.next_u64());
        values.push((time, value));
        crate::insert_value_by_time::<_, _, crate::PastQuotes<Test>>(key, time, value);

        let historical = crate::find_historical_values::<_, _, crate::PastQuotes<Test>>(
          key,
          time,
          core::time::Duration::from_millis(AGE_LIMIT),
          BOUND,
        );
        assert!(historical.len() <= BOUND);
        for (historical_time_encoding, historical_value) in historical.clone() {
          assert_eq!(values[0].0.lexicographic_encode(), historical_time_encoding);
          assert_eq!(values[0].1, historical_value);
          values.remove(0);
          assert_eq!(
            crate::PastQuotes::<Test>::take(key, historical_time_encoding),
            Some(historical_value)
          );
        }

        let no_more_historical = crate::find_historical_values::<_, _, crate::PastQuotes<Test>>(
          key,
          time,
          core::time::Duration::from_millis(AGE_LIMIT),
          BOUND,
        )
        .is_empty();
        assert_eq!(Some(values[0].0) > time.checked_sub(AGE_LIMIT), no_more_historical);
        if historical.len() < BOUND {
          assert!(no_more_historical);
        }
      }
    }
  });
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[test]
fn highest_value() {
  use rand_core::{RngCore as _, OsRng};

  new_test_ext().execute_with(|| {
    let key = ExternalCoin::Bitcoin;
    let mut values = vec![];
    for _ in 0 .. u16::MAX {
      if (OsRng.next_u64() & 1) == 1 {
        let value = if values.is_empty() || ((OsRng.next_u64() & 1) == 1) {
          OsRng.next_u64()
        } else {
          values[(OsRng.next_u64() as usize) % values.len()]
        };
        values.push(value);
        values.sort_unstable();
        crate::insert_possible_highest_value::<_, _, crate::HighestObservedMedian<Test>>(
          &key,
          &u128::from(value),
        );
        assert_eq!(
          crate::highest_value::<_, _, crate::HighestObservedMedian<Test>>(key),
          values.last().copied().map(u128::from)
        );
      }

      if (!values.is_empty()) && ((OsRng.next_u64() & 1) == 1) {
        let to_remove = (OsRng.next_u64() as usize) % values.len();
        crate::remove_possible_highest_value::<_, _, crate::HighestObservedMedian<Test>>(
          key,
          &u128::from(values[to_remove]),
        );
        values.remove(to_remove);
        assert_eq!(
          crate::highest_value::<_, _, crate::HighestObservedMedian<Test>>(key),
          values.last().copied().map(u128::from)
        );
      }
    }
  });
}

#[test]
fn economic_security_oracle() {
  for _ in 0 .. 4 {
    new_test_ext().execute_with(|| {
      Core::start_transaction(0);

      // 'Initialize' the pool
      LiquidityTokens::mint(
        SeraiAddress([0; 32]),
        Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) },
      )
      .unwrap();

      let mut first_value_pushed = None;
      let mut current_median = vec![];
      let mut highest_observed_median = 0;

      let iterations = OsRng.next_u64() % 1024;
      for i in 0 .. iterations {
        // Update the quote
        for coin in [Coin::Serai, Coin::External(ExternalCoin::Bitcoin)] {
          Coins::mint(
            serai_abi::dex::address(ExternalCoin::Bitcoin),
            Balance { coin, amount: Amount(OsRng.next_u64() / iterations) },
          )
          .unwrap();
        }

        // Update our median
        let quote = Dex::sri_quote(ExternalCoin::Bitcoin).unwrap();
        first_value_pushed = first_value_pushed.or(Some(quote));
        current_median.push(quote);

        current_median.sort_unstable();
        let observed_median = if (current_median.len() % 2) == 0 {
          current_median[current_median.len() / 2]
            .midpoint(current_median[(current_median.len() / 2) - 1])
        } else {
          current_median[current_median.len() / 2]
        };
        highest_observed_median = highest_observed_median.max(observed_median);

        // Run the `on_initialize` hook
        Timestamp::set_timestamp(i);
        EconomicSecurity::on_initialize(i);

        assert_eq!(
          EconomicSecurity::sri_value(ExternalBalance {
            coin: ExternalCoin::Bitcoin,
            amount: Amount(10u64.pow(ExternalCoin::Bitcoin.decimals()))
          }),
          Amount(u64::try_from(highest_observed_median).unwrap())
        );
      }
    });
  }
}

#[test]
fn economic_security_oracle_historical() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // 'Initialize' the pool
    LiquidityTokens::mint(
      SeraiAddress([0; 32]),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) },
    )
    .unwrap();

    // Push three values, where the median increases
    Coins::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: Coin::External(ExternalCoin::Bitcoin), amount: Amount(10) },
    )
    .unwrap();
    for i in 0 .. 3 {
      Coins::mint(
        serai_abi::dex::address(ExternalCoin::Bitcoin),
        Balance { coin: Coin::Serai, amount: Amount(2) },
      )
      .unwrap();
      Timestamp::set_timestamp(1 + i);
      EconomicSecurity::on_initialize(1 + i);
    }
    // With one more, we'd have 10 : 8, and a median of 10 : 5 (the midpoint of 10 : 4 and 10 : 6)
    // We do add one more, but with a timestamp such that the oldest value is considered historical
    Coins::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: Coin::Serai, amount: Amount(2) },
    )
    .unwrap();
    Timestamp::set_timestamp(1 + u64::try_from(crate::MEDIAN_LENGTH.as_millis()).unwrap());
    EconomicSecurity::on_initialize(4);
    // The median should now have three values, not four, and the oracle should yield as if 10 : 6
    assert_eq!(
      EconomicSecurity::sri_value(ExternalBalance {
        coin: ExternalCoin::Bitcoin,
        amount: Amount(10)
      }),
      Amount(6)
    );
  });
}

#[test]
fn economic_security_oracle_maximum_historical() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // 'Initialize' the pool
    LiquidityTokens::mint(
      SeraiAddress([0; 32]),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) },
    )
    .unwrap();

    // Push a large value at the very start
    Coins::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: Coin::Serai, amount: Amount(1_000) },
    )
    .unwrap();
    let mut sri_value = None;
    let mut sufficient_iterations = false;
    for i in 0 .. 100 {
      // Continually increase the amount of the external coin
      Coins::mint(
        serai_abi::dex::address(ExternalCoin::Bitcoin),
        Balance { coin: Coin::External(ExternalCoin::Bitcoin), amount: Amount(1) },
      )
      .unwrap();
      let time = 1 + (i * (u64::try_from(crate::MEDIAN_LENGTH.as_millis()).unwrap() - 1));
      Timestamp::set_timestamp(time);
      EconomicSecurity::on_initialize(1 + i);

      // Assert the `sri_value` continually decreases once the time exceeds `MAXIMUM_MEDIAN_LENGTH`
      let new_value = EconomicSecurity::sri_value(ExternalBalance {
        coin: ExternalCoin::Bitcoin,
        amount: Amount(1),
      });
      if sri_value.is_none() {
        sri_value = Some(new_value);
      }
      if time < u64::try_from(crate::MAXIMUM_MEDIAN_LENGTH.as_millis()).unwrap() {
        assert_eq!(sri_value.unwrap(), new_value);
      } else {
        sufficient_iterations = true;
        assert!(sri_value.unwrap() > new_value);
      }
    }
    assert!(sufficient_iterations);
  });
}

#[test]
fn economic_security_oracle_overflow() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // 'Initialize' the pool
    LiquidityTokens::mint(
      SeraiAddress([0; 32]),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) },
    )
    .unwrap();

    Coins::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) },
    )
    .unwrap();

    Coins::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance {
        coin: Coin::Serai,
        amount: Amount(u64::MAX / (10u64.pow(ExternalCoin::Bitcoin.decimals()) / 2)),
      },
    )
    .unwrap();

    Timestamp::set_timestamp(1);
    EconomicSecurity::on_initialize(1);

    assert_eq!(
      EconomicSecurity::sri_value(ExternalBalance {
        coin: ExternalCoin::Bitcoin,
        amount: Amount(10u64.pow(ExternalCoin::Bitcoin.decimals()))
      }),
      Amount(u64::MAX)
    );
  });
}

#[test]
fn economic_security_achieved() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    for network in ExternalNetworkId::all() {
      assert!(!EconomicSecurity::achieved_economic_security(network));
    }

    // Our `ValidatorSets` stub will immediately claim there's a satisfied requirement
    Timestamp::set_timestamp(1);
    EconomicSecurity::on_initialize(1);

    for network in ExternalNetworkId::all() {
      assert!(EconomicSecurity::achieved_economic_security(network));
    }
  });
}
