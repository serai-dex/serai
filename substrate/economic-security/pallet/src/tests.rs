use crate::mock::*;

use frame_support::traits::Hooks;
use frame_system::RawOrigin;

use sp_core::{sr25519::Signature, Pair as PairTrait};
use sp_runtime::BoundedVec;

use validator_sets::primitives::KeyPair;
use serai_primitives::{
  insecure_pair_from_name, Balance, Coin, ExternalBalance, ExternalCoin, ExternalNetworkId,
  EXTERNAL_COINS, EXTERNAL_NETWORKS,
};

fn set_keys_for_session(network: ExternalNetworkId) {
  ValidatorSets::set_keys(
    RawOrigin::None.into(),
    network,
    BoundedVec::new(),
    KeyPair(insecure_pair_from_name("Alice").public(), vec![].try_into().unwrap()),
    Signature([0u8; 64]),
  )
  .unwrap();
}

fn make_pool_with_liquidity(coin: &ExternalCoin) {
  // make a pool so that we have security oracle value for the coin
  let liq_acc = insecure_pair_from_name("liq-acc").public();
  let balance = ExternalBalance { coin: *coin, amount: key_shares()[&coin.network().into()] };
  Coins::mint(liq_acc, balance.into()).unwrap();
  Coins::mint(liq_acc, Balance { coin: Coin::Serai, amount: balance.amount }).unwrap();

  Dex::add_liquidity(
    RawOrigin::Signed(liq_acc).into(),
    *coin,
    balance.amount.0 / 2,
    balance.amount.0 / 2,
    1,
    1,
    liq_acc,
  )
  .unwrap();
  Dex::on_finalize(1);
  assert!(Dex::security_oracle_value(coin).unwrap().0 > 0)
}

#[test]
fn economic_security() {
  new_test_ext().execute_with(|| {
    // update the state
    EconomicSecurity::on_initialize(1);

    // make sure it is right at the beginning
    // this is none at this point since no set has set their keys so TAS isn't up-to-date
    for network in EXTERNAL_NETWORKS {
      assert_eq!(EconomicSecurity::economic_security_block(network), None);
    }

    // set the keys for TAS and have pools for oracle value
    for coin in EXTERNAL_COINS {
      set_keys_for_session(coin.network());
      make_pool_with_liquidity(&coin);
    }

    // update the state
    EconomicSecurity::on_initialize(1);

    // check again. The reason we have economic security now is because we stake a key share
    // per participant per network(total of 4 key share) in genesis for all networks.
    for network in EXTERNAL_NETWORKS {
      assert_eq!(EconomicSecurity::economic_security_block(network), Some(1));
    }

    // TODO: Not sure how much sense this test makes since we start from an economically secure
    // state. Ideally we should start from not economically secure state and stake the necessary
    // amount and then check whether the pallet set the value right since that will be the mainnet
    // path. But we cant do that at the moment since vs-pallet genesis build auto stake per network
    // to construct the set. This also makes a missing piece of logic explicit. We need genesis
    // validators to be in-set but without their stake, or at least its affect on TAS. So this test
    // should be updated once that logic is coded.
  });
}
