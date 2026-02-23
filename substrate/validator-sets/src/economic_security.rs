// TODO: Move most of this file to `serai-economic-security-pallet`.

use serai_abi::{
  primitives::{
    network_id::{ExternalNetworkId, NetworkId},
    coin::Coin,
    balance::{Amount, ExternalBalance, Balance},
  },
  economic_security::EconomicSecurity,
};

use serai_coins_pallet::{CoinsInstance, Config as CoinsConfig};

use super::Coins;

pub(crate) fn include_genesis_validators<T: CoinsConfig<CoinsInstance>, E: EconomicSecurity>(
  network: impl Into<NetworkId>,
) -> bool {
  match network.into() {
    // For Serai, we include the genesis validators as long as any other set would
    NetworkId::Serai => ExternalNetworkId::all().any(include_genesis_validators::<T, E>),
    // For external networks, we include the genesis validators if pre-economic security
    NetworkId::External(network) => !E::achieved_economic_security(network),
  }
}

/// The required amount of SRI which must be allocated as stake for a network to be considered
/// economically secure regarding the total amount of coins.
///
/// This evaluates the stake required to secure the amount of coins with the valuation from the
/// economic security oracle, without any buffer.
///
/// This accepts a `proposed_additional_balance` which, if present, will be added to the relevant
/// supply when performing the calculation. The balance's coin's network MUST be `network` for
/// this to be sound. This has undefined behavior if it isn't.
///
/// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
/// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
pub fn coins_stake_requirement<T: CoinsConfig<CoinsInstance>, E: EconomicSecurity>(
  network: ExternalNetworkId,
  proposed_additional_balance: Option<Balance>,
) -> Amount {
  let mut requirement = Amount(0).0;
  for coin in network.coins() {
    let mut coin_supply = Coins::<T>::supply(Coin::from(coin));
    if let Some(proposed_additional_balance) = proposed_additional_balance {
      if proposed_additional_balance.coin == Coin::External(coin) {
        coin_supply.0 = coin_supply.0.saturating_add(proposed_additional_balance.amount.0);
      }
    }

    let stake_for_balance = {
      let value = E::sri_value(ExternalBalance { coin, amount: coin_supply });
      // As 67% can execute signing protocols, 67% of stake must be sufficient to secure this
      let requirement = (u128::from(value.0) * 3).div_ceil(2);
      u64::try_from(requirement).unwrap_or(u64::MAX)
    };

    requirement = requirement.saturating_add(stake_for_balance);
  }
  Amount(requirement)
}

/// The required amount of SRI which must be allocated as stake for a network to be considered
/// economically secure regarding the coins in the liquidity pool.
///
/// This evaluates the stake required to secure the amount of coins within the liquidity pool with
/// the valuation from the economic security oracle, with an additional buffer for safety.
///
/// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
/// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
pub fn liquidity_stake_requirement<T: CoinsConfig<CoinsInstance>, E: EconomicSecurity>(
  network: ExternalNetworkId,
) -> Amount {
  let mut requirement = Amount(0).0;
  for coin in network.coins() {
    let liquidity_pool_balance =
      Coins::<T>::balance(serai_abi::dex::address(coin), Coin::from(coin));

    let stake_for_balance = {
      let value = E::sri_value(ExternalBalance { coin, amount: liquidity_pool_balance });
      // As 67% can execute signing protocols, 67% of stake must be sufficient to secure this
      let requirement = (u128::from(value.0) * 3).div_ceil(2);
      // We require an additional margin of 20%
      let margin = requirement.div_ceil(5);
      u64::try_from(requirement.saturating_add(margin)).unwrap_or(u64::MAX)
    };

    requirement = requirement.saturating_add(stake_for_balance);
  }
  Amount(requirement)
}

/// The required amount of SRI which must be allocated as stake for a network to be considered
/// economically secure.
///
/// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
/// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
pub fn network_stake_requirement<T: CoinsConfig<CoinsInstance>, E: EconomicSecurity>(
  network: ExternalNetworkId,
) -> Amount {
  coins_stake_requirement::<T, E>(network, None).max(liquidity_stake_requirement::<T, E>(network))
}

#[cfg(test)]
#[expect(clippy::as_conversions, clippy::same_name_method)]
mod mock {
  use frame_support::{weights::Weight, derive_impl, construct_runtime};

  use serai_abi::primitives::{coin::Coin, address::SeraiAddress};

  use serai_coins_pallet::{CoinsInstance, AlwaysAllowMint};

  pub const STAKE_REQUIREMENT: u64 = 30_000 * 10u64.pow(Coin::Serai.decimals());

  construct_runtime!(
    pub enum Test
    {
      System: frame_system,
      Timestamp: pallet_timestamp,
      Core: serai_core_pallet,
      Coins: serai_coins_pallet::<CoinsInstance>,
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

  impl serai_coins_pallet::Config<CoinsInstance> for Test {
    type AllowMint = AlwaysAllowMint;
    type Weights = ();
  }

  pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let mut externalities = sp_io::TestExternalities::new_empty();
    externalities.execute_with(|| {
      let system = frame_system::GenesisConfig::<Test>::default();
      let coins = serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
        accounts: vec![],
        _instance: Default::default(),
      };
      Core::genesis(&RuntimeGenesisConfig { system, coins });
    });
    externalities
  }
}

#[test]
fn test_include_genesis_validators() {
  use rand_core::{RngCore as _, OsRng};

  use mock::Test;
  use sp_io::TestExternalities;
  use serai_abi::primitives::address::SeraiAddress;

  use crate::{
    MockStorage,
    allocations::{Allocations as _, AllocationsStorage},
  };

  let rand_key = || {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    SeraiAddress(key)
  };

  TestExternalities::default().execute_with(|| {
    let increase_allocation = |network: NetworkId, amount: Amount| {
      const ALLOCATIONS_PER_KEY_SHARE: Amount = Amount(10_000 * 10u64.pow(Coin::Serai.decimals()));

      // set allocations per key share so that we can allocate first
      <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
        network,
        ALLOCATIONS_PER_KEY_SHARE,
      );

      let validator = rand_key();
      MockStorage::set_random_auxiliary_keys(validator);
      MockStorage::increase_allocation_without_updating_other_contexts(
        network, validator, amount, false,
      )
      .unwrap();
    };

    // should return true for all networks initially since none of them reach economic security
    for n in NetworkId::all() {
      assert!(include_genesis_validators::<Test, MockStorage>(n));
    }

    // make only one network reach economic security
    increase_allocation(ExternalNetworkId::Bitcoin.into(), Amount(mock::STAKE_REQUIREMENT));

    // should return true for all external networks except Bitcoin since its only one
    // that achieved economic security in this case.
    for n in ExternalNetworkId::all() {
      if n == ExternalNetworkId::Bitcoin {
        assert!(!include_genesis_validators::<Test, MockStorage>(n));
      } else {
        assert!(include_genesis_validators::<Test, MockStorage>(n));
      }
    }

    // should return true for serai since we have at least 1 network that didn't reach
    // economic security
    assert!(include_genesis_validators::<Test, MockStorage>(NetworkId::Serai));

    // make remaining external network reach economic security
    for network in ExternalNetworkId::all() {
      if network == ExternalNetworkId::Bitcoin {
        continue;
      }
      increase_allocation(network.into(), Amount(mock::STAKE_REQUIREMENT));
    }

    // now, we should get false for all external networks
    for n in ExternalNetworkId::all() {
      assert!(!include_genesis_validators::<Test, MockStorage>(n));
    }

    // now, should also get false for serai since all external networks reached economic security
    assert!(!include_genesis_validators::<Test, MockStorage>(NetworkId::Serai));
  })
}

#[test]
fn test_coins_stake_requirement() {
  use rand_core::{RngCore as _, OsRng};
  use serai_abi::{
    primitives::{coin::ExternalCoin, address::SeraiAddress},
    TransactionContext as _,
  };
  use mock::{Test, Core};
  use crate::MockStorage;

  let rand_key = || {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    SeraiAddress(key)
  };

  mock::new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let required_stake = |balance: ExternalBalance| -> u64 {
      let value = (u128::from(MockStorage::sri_value(balance).0) * 3).div_ceil(2);
      u64::try_from(value).unwrap()
    };

    // should return 0 if no supply for any coin in the network
    let coin = ExternalCoin::Ether;
    assert_eq!(coins_stake_requirement::<Test, MockStorage>(coin.network(), None), Amount(0));

    // have some supply
    let balance = ExternalBalance { coin, amount: Amount(123 * 10u64.pow(coin.decimals())) };
    Coins::<Test>::mint(rand_key(), Balance::from(balance)).unwrap();

    // should return correct required value if we have supply
    let mut expected_value = required_stake(balance);
    assert_eq!(
      coins_stake_requirement::<Test, MockStorage>(coin.network(), None),
      Amount(expected_value)
    );

    // add more supply for the same network but different coin
    let coin = ExternalCoin::Dai;
    let balance = ExternalBalance { coin, amount: Amount(555 * 10u64.pow(coin.decimals())) };
    Coins::<Test>::mint(rand_key(), Balance::from(balance)).unwrap();

    // we now should get the correct total requirement
    expected_value = expected_value.saturating_add(required_stake(balance));
    assert_eq!(
      coins_stake_requirement::<Test, MockStorage>(coin.network(), None),
      Amount(expected_value)
    );

    // we should still get the correct value if we provide optional additional supply
    let balance = ExternalBalance { coin, amount: Amount(22 * 10u64.pow(coin.decimals())) };
    expected_value = expected_value.saturating_add(required_stake(balance));
    assert_eq!(
      coins_stake_requirement::<Test, MockStorage>(coin.network(), Some(Balance::from(balance))),
      Amount(expected_value)
    );
  });
}

#[test]
fn test_liquidity_stake_requirement() {
  use serai_abi::{primitives::coin::ExternalCoin, TransactionContext as _};
  use mock::{Test, Core};
  use crate::MockStorage;

  mock::new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let required_stake = |balance: ExternalBalance| -> u64 {
      let value = (u128::from(MockStorage::sri_value(balance).0) * 3).div_ceil(2);
      let additional = value.div_ceil(5);
      u64::try_from(value.saturating_add(additional)).unwrap()
    };

    // should return 0 if no liquidity for any coin in the network
    let coin = ExternalCoin::Ether;
    assert_eq!(liquidity_stake_requirement::<Test, MockStorage>(coin.network()), Amount(0));

    // have some liquidity
    let balance = ExternalBalance { coin, amount: Amount(123 * 10u64.pow(coin.decimals())) };
    Coins::<Test>::mint(serai_abi::dex::address(coin), Balance::from(balance)).unwrap();

    // should return correct required value if we have liquidity
    let mut expected_value = required_stake(balance);
    assert_eq!(
      liquidity_stake_requirement::<Test, MockStorage>(coin.network()),
      Amount(expected_value)
    );

    // add more liquidity for the same network but different coin
    let coin = ExternalCoin::Dai;
    let balance = ExternalBalance { coin, amount: Amount(555 * 10u64.pow(coin.decimals())) };
    Coins::<Test>::mint(serai_abi::dex::address(coin), Balance::from(balance)).unwrap();

    // we now should get the correct total requirement
    expected_value = expected_value.saturating_add(required_stake(balance));
    assert_eq!(
      liquidity_stake_requirement::<Test, MockStorage>(coin.network()),
      Amount(expected_value)
    );
  });
}

#[test]
fn test_network_stake_requirement() {
  use rand_core::{RngCore as _, OsRng};
  use serai_abi::{
    primitives::{coin::ExternalCoin, address::SeraiAddress},
    TransactionContext as _,
  };
  use mock::{Test, Core};
  use crate::MockStorage;

  let rand_key = || {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    SeraiAddress(key)
  };

  mock::new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let required_coins_stake = |balance: ExternalBalance| -> u64 {
      let value = (u128::from(MockStorage::sri_value(balance).0) * 3).div_ceil(2);
      u64::try_from(value).unwrap()
    };
    let required_liquidity_stake = |balance: ExternalBalance| -> u64 {
      let value = (u128::from(MockStorage::sri_value(balance).0) * 3).div_ceil(2);
      let additional = value.div_ceil(5);
      u64::try_from(value.saturating_add(additional)).unwrap()
    };

    // should return 0 if no supply for any coin in the network
    let coin = ExternalCoin::Ether;
    assert_eq!(network_stake_requirement::<Test, MockStorage>(coin.network()), Amount(0));

    // have some liquidity
    let liquidity_amount = Amount(123 * 10u64.pow(coin.decimals()));
    let balance = ExternalBalance { coin, amount: liquidity_amount };
    Coins::<Test>::mint(serai_abi::dex::address(coin), Balance::from(balance)).unwrap();

    // should return liquidity stake requirement, since we have 0 requirement for the coins yet
    let mut expected_value = required_liquidity_stake(balance);
    assert_eq!(
      network_stake_requirement::<Test, MockStorage>(coin.network()),
      Amount(expected_value)
    );

    // add some supply now
    let balance = ExternalBalance { coin, amount: Amount(555 * 10u64.pow(coin.decimals())) };
    Coins::<Test>::mint(rand_key(), Balance::from(balance)).unwrap();

    // we now should get the coins requirement since it should be bigger
    expected_value = required_coins_stake(balance) +
      required_coins_stake(ExternalBalance { coin, amount: liquidity_amount });
    assert_eq!(
      network_stake_requirement::<Test, MockStorage>(coin.network()),
      Amount(expected_value)
    );
  });
}
