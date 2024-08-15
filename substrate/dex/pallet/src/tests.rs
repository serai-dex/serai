// This file was originally:

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// It has been forked into a crate distributed under the AGPL 3.0.
// Please check the current distribution for up-to-date copyright and licensing information.

use crate::{mock::*, *};
use frame_support::{assert_noop, assert_ok};

pub use coins_pallet as coins;

use coins::Pallet as CoinsPallet;

use serai_primitives::{Balance, COINS, PublicKey, system_address, Amount};

type LiquidityTokens<T> = coins_pallet::Pallet<T, coins::Instance1>;
type LiquidityTokensError<T> = coins_pallet::Error<T, coins::Instance1>;

fn events() -> Vec<Event<Test>> {
  let result = System::events()
    .into_iter()
    .map(|r| r.event)
    .filter_map(|e| if let mock::RuntimeEvent::Dex(inner) = e { Some(inner) } else { None })
    .collect();

  System::reset_events();

  result
}

fn pools() -> Vec<PoolId> {
  let mut s: Vec<_> = Pools::<Test>::iter().map(|x| x.0).collect();
  s.sort();
  s
}

fn coins() -> Vec<Coin> {
  COINS.to_vec()
}

fn balance(owner: PublicKey, coin: Coin) -> u64 {
  CoinsPallet::<Test>::balance(owner, coin).0
}

fn pool_balance(owner: PublicKey, token_id: Coin) -> u64 {
  LiquidityTokens::<Test>::balance(owner, token_id).0
}

macro_rules! bvec {
	($( $x:tt )*) => {
		vec![$( $x )*].try_into().unwrap()
	}
}

#[test]
fn check_pool_accounts_dont_collide() {
  use std::collections::HashSet;
  let mut map = HashSet::new();

  for coin in coins() {
    let account = Dex::get_pool_account(coin);
    if map.contains(&account) {
      panic!("Collision at {coin:?}");
    }
    map.insert(account);
  }
}

#[test]
fn check_max_numbers() {
  new_test_ext().execute_with(|| {
    assert_eq!(Dex::quote(3u64, u64::MAX, u64::MAX).ok().unwrap(), 3);
    assert!(Dex::quote(u64::MAX, 3u64, u64::MAX).is_err());
    assert_eq!(Dex::quote(u64::MAX, u64::MAX, 1u64).ok().unwrap(), 1);

    assert_eq!(Dex::get_amount_out(100u64, u64::MAX, u64::MAX).ok().unwrap(), 99);
    assert_eq!(Dex::get_amount_in(100u64, u64::MAX, u64::MAX).ok().unwrap(), 101);
  });
}

#[test]
fn can_create_pool() {
  new_test_ext().execute_with(|| {
    let coin_account_deposit: u64 = 0;
    let user: PublicKey = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Monero;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(1000) }));
    assert_ok!(Dex::create_pool(coin2));

    assert_eq!(balance(user, coin1), 1000 - coin_account_deposit);

    assert_eq!(
      events(),
      [Event::<Test>::PoolCreated { pool_id, pool_account: Dex::get_pool_account(pool_id) }]
    );
    assert_eq!(pools(), vec![pool_id]);

    assert_noop!(Dex::create_pool(coin1), Error::<Test>::EqualCoins);
  });
}

#[test]
fn create_same_pool_twice_should_fail() {
  new_test_ext().execute_with(|| {
    let coin = Coin::Dai;
    assert_ok!(Dex::create_pool(coin));
    assert_noop!(Dex::create_pool(coin), Error::<Test>::PoolExists);
  });
}

#[test]
fn different_pools_should_have_different_lp_tokens() {
  new_test_ext().execute_with(|| {
    let coin1 = Coin::native();
    let coin2 = Coin::Bitcoin;
    let coin3 = Coin::Ether;
    let pool_id_1_2 = Dex::get_pool_id(coin1, coin2).unwrap();
    let pool_id_1_3 = Dex::get_pool_id(coin1, coin3).unwrap();

    let lp_token2_1 = coin2;
    assert_ok!(Dex::create_pool(coin2));
    let lp_token3_1 = coin3;

    assert_eq!(
      events(),
      [Event::<Test>::PoolCreated {
        pool_id: pool_id_1_2,
        pool_account: Dex::get_pool_account(pool_id_1_2),
      }]
    );

    assert_ok!(Dex::create_pool(coin3));
    assert_eq!(
      events(),
      [Event::<Test>::PoolCreated {
        pool_id: pool_id_1_3,
        pool_account: Dex::get_pool_account(pool_id_1_3),
      }]
    );

    assert_ne!(lp_token2_1, lp_token3_1);
  });
}

#[test]
fn can_add_liquidity() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Dai;
    let coin3 = Coin::Monero;

    let lp_token1 = coin2;
    assert_ok!(Dex::create_pool(coin2));
    let lp_token2 = coin3;
    assert_ok!(Dex::create_pool(coin3));

    assert_ok!(CoinsPallet::<Test>::mint(
      user,
      Balance { coin: coin1, amount: Amount(10000 * 2 + 1) }
    ));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin3, amount: Amount(1000) }));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 10, 10000, 10, 10000, user,));

    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();
    assert!(events().contains(&Event::<Test>::LiquidityAdded {
      who: user,
      mint_to: user,
      pool_id,
      sri_amount: 10000,
      coin_amount: 10,
      lp_token_minted: 216,
    }));
    let pallet_account = Dex::get_pool_account(pool_id);
    assert_eq!(balance(pallet_account, coin1), 10000);
    assert_eq!(balance(pallet_account, coin2), 10);
    assert_eq!(balance(user, coin1), 10000 + 1);
    assert_eq!(balance(user, coin2), 1000 - 10);
    assert_eq!(pool_balance(user, lp_token1), 216);

    // try to pass the non-native - native coins, the result should be the same
    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin3, 10, 10000, 10, 10000, user,));

    let pool_id = Dex::get_pool_id(coin1, coin3).unwrap();
    assert!(events().contains(&Event::<Test>::LiquidityAdded {
      who: user,
      mint_to: user,
      pool_id,
      sri_amount: 10000,
      coin_amount: 10,
      lp_token_minted: 216,
    }));
    let pallet_account = Dex::get_pool_account(pool_id);
    assert_eq!(balance(pallet_account, coin1), 10000);
    assert_eq!(balance(pallet_account, coin3), 10);
    assert_eq!(balance(user, coin1), 1);
    assert_eq!(balance(user, coin3), 1000 - 10);
    assert_eq!(pool_balance(user, lp_token2), 216);
  });
}

#[test]
fn add_tiny_liquidity_leads_to_insufficient_liquidity_minted_error() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Bitcoin;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(1000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    assert_noop!(
      Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 1, 1, 1, 1, user),
      Error::<Test>::InsufficientLiquidityMinted
    );
  });
}

#[test]
fn add_tiny_liquidity_directly_to_pool_address() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;
    let coin3 = Coin::Dai;

    assert_ok!(Dex::create_pool(coin2));
    assert_ok!(Dex::create_pool(coin3));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000 * 2) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin3, amount: Amount(10000) }));

    // check we're still able to add the liquidity even when the pool already has some coin1
    let pallet_account = Dex::get_pool_account(Dex::get_pool_id(coin1, coin2).unwrap());
    assert_ok!(CoinsPallet::<Test>::mint(
      pallet_account,
      Balance { coin: coin1, amount: Amount(1000) }
    ));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 10, 10000, 10, 10000, user,));

    // check the same but for coin3 (non-native token)
    let pallet_account = Dex::get_pool_account(Dex::get_pool_id(coin1, coin3).unwrap());
    assert_ok!(CoinsPallet::<Test>::mint(
      pallet_account,
      Balance { coin: coin2, amount: Amount(1) }
    ));
    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin3, 10, 10000, 10, 10000, user,));
  });
}

#[test]
fn can_remove_liquidity() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Monero;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();

    let lp_token = coin2;
    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(
      user,
      Balance { coin: coin1, amount: Amount(10000000000) }
    ));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(100000) }));

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      100000,
      1000000000,
      100000,
      1000000000,
      user,
    ));

    let total_lp_received = pool_balance(user, lp_token);

    assert_ok!(Dex::remove_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      total_lp_received,
      0,
      0,
      user,
    ));

    assert!(events().contains(&Event::<Test>::LiquidityRemoved {
      who: user,
      withdraw_to: user,
      pool_id,
      sri_amount: 999990000,
      coin_amount: 99999,
      lp_token_burned: total_lp_received,
    }));

    let pool_account = Dex::get_pool_account(pool_id);
    assert_eq!(balance(pool_account, coin1), 10000);
    assert_eq!(balance(pool_account, coin2), 1);
    assert_eq!(pool_balance(pool_account, lp_token), 100);

    assert_eq!(balance(user, coin1), 10000000000 - 1000000000 + 999990000);
    assert_eq!(balance(user, coin2), 99999);
    assert_eq!(pool_balance(user, lp_token), 0);
  });
}

#[test]
fn can_not_redeem_more_lp_tokens_than_were_minted() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Dai;
    let lp_token = coin2;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 10, 10000, 10, 10000, user,));

    // Only 216 lp_tokens_minted
    assert_eq!(pool_balance(user, lp_token), 216);

    assert_noop!(
      Dex::remove_liquidity(
        RuntimeOrigin::signed(user),
        coin2,
        216 + 1, // Try and redeem 10 lp tokens while only 9 minted.
        0,
        0,
        user,
      ),
      LiquidityTokensError::<Test>::NotEnoughCoins
    );
  });
}

#[test]
fn can_quote_price() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(100000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 200, 10000, 1, 1, user,));

    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, 3000, false,),
      Some(60)
    );
    // including fee so should get less out...
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, 3000, true,),
      Some(46)
    );
    // Check it still gives same price:
    // (if the above accidentally exchanged then it would not give same quote as before)
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, 3000, false,),
      Some(60)
    );
    // including fee so should get less out...
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, 3000, true,),
      Some(46)
    );

    // Check inverse:
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(coin2, Coin::native(), 60, false,),
      Some(3000)
    );
    // including fee so should get less out...
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(coin2, Coin::native(), 60, true,),
      Some(2302)
    );

    //
    // same tests as above but for quote_price_tokens_for_exact_tokens:
    //
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, 60, false,),
      Some(3000)
    );
    // including fee so should need to put more in...
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, 60, true,),
      Some(4299)
    );
    // Check it still gives same price:
    // (if the above accidentally exchanged then it would not give same quote as before)
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, 60, false,),
      Some(3000)
    );
    // including fee so should need to put more in...
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, 60, true,),
      Some(4299)
    );

    // Check inverse:
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(coin2, Coin::native(), 3000, false,),
      Some(60)
    );
    // including fee so should need to put more in...
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(coin2, Coin::native(), 3000, true,),
      Some(86)
    );

    //
    // roundtrip: Without fees one should get the original number
    //
    let amount_in = 100;

    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(coin2, Coin::native(), amount_in, false,).and_then(
        |amount| Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, amount, false,)
      ),
      Some(amount_in)
    );
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(Coin::native(), coin2, amount_in, false,).and_then(
        |amount| Dex::quote_price_exact_tokens_for_tokens(coin2, Coin::native(), amount, false,)
      ),
      Some(amount_in)
    );

    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(coin2, Coin::native(), amount_in, false,).and_then(
        |amount| Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, amount, false,)
      ),
      Some(amount_in)
    );
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(Coin::native(), coin2, amount_in, false,).and_then(
        |amount| Dex::quote_price_tokens_for_exact_tokens(coin2, Coin::native(), amount, false,)
      ),
      Some(amount_in)
    );
  });
}

#[test]
fn quote_price_exact_tokens_for_tokens_matches_execution() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let user2 = system_address(b"user2").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Bitcoin;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(100000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 200, 10000, 1, 1, user,));

    let amount = 1;
    let quoted_price = 49;
    assert_eq!(
      Dex::quote_price_exact_tokens_for_tokens(coin2, coin1, amount, true,),
      Some(quoted_price)
    );

    assert_ok!(CoinsPallet::<Test>::mint(user2, Balance { coin: coin2, amount: Amount(amount) }));
    let prior_sri_balance = 0;
    assert_eq!(prior_sri_balance, balance(user2, coin1));
    assert_ok!(Dex::swap_exact_tokens_for_tokens(
      RuntimeOrigin::signed(user2),
      bvec![coin2, coin1],
      amount,
      1,
      user2,
    ));

    assert_eq!(prior_sri_balance + quoted_price, balance(user2, coin1));
  });
}

#[test]
fn quote_price_tokens_for_exact_tokens_matches_execution() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let user2 = system_address(b"user2").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Monero;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(100000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 200, 10000, 1, 1, user,));

    let amount = 49;
    let quoted_price = 1;
    assert_eq!(
      Dex::quote_price_tokens_for_exact_tokens(coin2, coin1, amount, true,),
      Some(quoted_price)
    );

    assert_ok!(CoinsPallet::<Test>::mint(user2, Balance { coin: coin2, amount: Amount(amount) }));
    let prior_sri_balance = 0;
    assert_eq!(prior_sri_balance, balance(user2, coin1));
    let prior_coin_balance = 49;
    assert_eq!(prior_coin_balance, balance(user2, coin2));
    assert_ok!(Dex::swap_tokens_for_exact_tokens(
      RuntimeOrigin::signed(user2),
      bvec![coin2, coin1],
      amount,
      1,
      user2,
    ));

    assert_eq!(prior_sri_balance + amount, balance(user2, coin1));
    assert_eq!(prior_coin_balance - quoted_price, balance(user2, coin2));
  });
}

#[test]
fn can_swap_with_native() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));

    let input_amount = 100;
    let expect_receive = Dex::get_amount_out(input_amount, liquidity2, liquidity1).ok().unwrap();

    assert_ok!(Dex::swap_exact_tokens_for_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin2, coin1],
      input_amount,
      1,
      user,
    ));

    let pallet_account = Dex::get_pool_account(pool_id);
    assert_eq!(balance(user, coin1), expect_receive);
    assert_eq!(balance(user, coin2), 1000 - liquidity2 - input_amount);
    assert_eq!(balance(pallet_account, coin1), liquidity1 - expect_receive);
    assert_eq!(balance(pallet_account, coin2), liquidity2 + input_amount);
  });
}

#[test]
fn can_swap_with_realistic_values() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let sri = Coin::native();
    let dai = Coin::Dai;
    assert_ok!(Dex::create_pool(dai));

    const UNIT: u64 = 1_000_000_000;

    assert_ok!(CoinsPallet::<Test>::mint(
      user,
      Balance { coin: sri, amount: Amount(300_000 * UNIT) }
    ));
    assert_ok!(CoinsPallet::<Test>::mint(
      user,
      Balance { coin: dai, amount: Amount(1_100_000 * UNIT) }
    ));

    let liquidity_sri = 200_000 * UNIT; // ratio for a 5$ price
    let liquidity_dai = 1_000_000 * UNIT;
    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      dai,
      liquidity_dai,
      liquidity_sri,
      1,
      1,
      user,
    ));

    let input_amount = 10 * UNIT; // dai

    assert_ok!(Dex::swap_exact_tokens_for_tokens(
      RuntimeOrigin::signed(user),
      bvec![dai, sri],
      input_amount,
      1,
      user,
    ));

    assert!(events().contains(&Event::<Test>::SwapExecuted {
      who: user,
      send_to: user,
      path: bvec![dai, sri],
      amount_in: 10 * UNIT,      // usd
      amount_out: 1_993_980_120, // About 2 dot after div by UNIT.
    }));
  });
}

#[test]
fn can_not_swap_in_pool_with_no_liquidity_added_yet() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Monero;

    assert_ok!(Dex::create_pool(coin2));

    // Check can't swap an empty pool
    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin2, coin1],
        10,
        1,
        user,
      ),
      Error::<Test>::PoolNotFound
    );
  });
}

#[test]
fn check_no_panic_when_try_swap_close_to_empty_pool() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Bitcoin;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();
    let lp_token = coin2;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));

    let lp_token_minted = pool_balance(user, lp_token);
    assert!(events().contains(&Event::<Test>::LiquidityAdded {
      who: user,
      mint_to: user,
      pool_id,
      sri_amount: liquidity1,
      coin_amount: liquidity2,
      lp_token_minted,
    }));

    let pallet_account = Dex::get_pool_account(pool_id);
    assert_eq!(balance(pallet_account, coin1), liquidity1);
    assert_eq!(balance(pallet_account, coin2), liquidity2);

    assert_ok!(Dex::remove_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      lp_token_minted,
      1,
      1,
      user,
    ));

    // Now, the pool should exist but be almost empty.
    // Let's try and drain it.
    assert_eq!(balance(pallet_account, coin1), 708);
    assert_eq!(balance(pallet_account, coin2), 15);

    // validate the reserve should always stay above the ED
    // Following test fail again due to the force on ED being > 1.
    // assert_noop!(
    // 	Dex::swap_tokens_for_exact_tokens(
    // 		RuntimeOrigin::signed(user),
    // 		bvec![coin2, coin1],
    // 		708 - ed + 1, // amount_out
    // 		500,          // amount_in_max
    // 		user,
    // 	),
    // 	Error::<Test>::ReserveLeftLessThanMinimum
    // );

    assert_ok!(Dex::swap_tokens_for_exact_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin2, coin1],
      608, // amount_out
      500, // amount_in_max
      user,
    ));

    let token_1_left = balance(pallet_account, coin1);
    let token_2_left = balance(pallet_account, coin2);
    assert_eq!(token_1_left, 708 - 608);

    // The price for the last tokens should be very high
    assert_eq!(
      Dex::get_amount_in(token_1_left - 1, token_2_left, token_1_left).ok().unwrap(),
      10625
    );

    assert_noop!(
      Dex::swap_tokens_for_exact_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin2, coin1],
        token_1_left - 1, // amount_out
        1000,             // amount_in_max
        user,
      ),
      Error::<Test>::ProvidedMaximumNotSufficientForSwap
    );

    // Try to swap what's left in the pool
    assert_noop!(
      Dex::swap_tokens_for_exact_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin2, coin1],
        token_1_left, // amount_out
        1000,         // amount_in_max
        user,
      ),
      Error::<Test>::AmountOutTooHigh
    );
  });
}

#[test]
fn swap_should_not_work_if_too_much_slippage() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));

    let exchange_amount = 100;

    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin2, coin1],
        exchange_amount, // amount_in
        4000,            // amount_out_min
        user,
      ),
      Error::<Test>::ProvidedMinimumNotSufficientForSwap
    );
  });
}

#[test]
fn can_swap_tokens_for_exact_tokens() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Dai;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(20000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    let pallet_account = Dex::get_pool_account(pool_id);
    let before1 = balance(pallet_account, coin1) + balance(user, coin1);
    let before2 = balance(pallet_account, coin2) + balance(user, coin2);

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));

    let exchange_out = 50;
    let expect_in = Dex::get_amount_in(exchange_out, liquidity1, liquidity2).ok().unwrap();

    assert_ok!(Dex::swap_tokens_for_exact_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin1, coin2],
      exchange_out, // amount_out
      3500,         // amount_in_max
      user,
    ));

    assert_eq!(balance(user, coin1), 10000 - expect_in);
    assert_eq!(balance(user, coin2), 1000 - liquidity2 + exchange_out);
    assert_eq!(balance(pallet_account, coin1), liquidity1 + expect_in);
    assert_eq!(balance(pallet_account, coin2), liquidity2 - exchange_out);

    // check invariants:

    // native and coin totals should be preserved.
    assert_eq!(before1, balance(pallet_account, coin1) + balance(user, coin1));
    assert_eq!(before2, balance(pallet_account, coin2) + balance(user, coin2));
  });
}

#[test]
fn can_swap_tokens_for_exact_tokens_when_not_liquidity_provider() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let user2 = system_address(b"user2").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Monero;
    let pool_id = Dex::get_pool_id(coin1, coin2).unwrap();
    let lp_token = coin2;

    assert_ok!(Dex::create_pool(coin2));

    let base1 = 10000;
    let base2 = 1000;
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(base1) }));
    assert_ok!(CoinsPallet::<Test>::mint(user2, Balance { coin: coin1, amount: Amount(base1) }));
    assert_ok!(CoinsPallet::<Test>::mint(user2, Balance { coin: coin2, amount: Amount(base2) }));

    let pallet_account = Dex::get_pool_account(pool_id);
    let before1 = balance(pallet_account, coin1) + balance(user, coin1) + balance(user2, coin1);
    let before2 = balance(pallet_account, coin2) + balance(user, coin2) + balance(user2, coin2);

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user2),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user2,
    ));

    assert_eq!(balance(user, coin1), base1);
    assert_eq!(balance(user, coin2), 0);

    let exchange_out = 50;
    let expect_in = Dex::get_amount_in(exchange_out, liquidity1, liquidity2).ok().unwrap();

    assert_ok!(Dex::swap_tokens_for_exact_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin1, coin2],
      exchange_out, // amount_out
      3500,         // amount_in_max
      user,
    ));

    assert_eq!(balance(user, coin1), base1 - expect_in);
    assert_eq!(balance(pallet_account, coin1), liquidity1 + expect_in);
    assert_eq!(balance(user, coin2), exchange_out);
    assert_eq!(balance(pallet_account, coin2), liquidity2 - exchange_out);

    // check invariants:

    // native and coin totals should be preserved.
    assert_eq!(
      before1,
      balance(pallet_account, coin1) + balance(user, coin1) + balance(user2, coin1)
    );
    assert_eq!(
      before2,
      balance(pallet_account, coin2) + balance(user, coin2) + balance(user2, coin2)
    );

    let lp_token_minted = pool_balance(user2, lp_token);
    assert_eq!(lp_token_minted, 1314);

    assert_ok!(Dex::remove_liquidity(
      RuntimeOrigin::signed(user2),
      coin2,
      lp_token_minted,
      0,
      0,
      user2,
    ));
  });
}

#[test]
fn swap_tokens_for_exact_tokens_should_not_work_if_too_much_slippage() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;

    assert_ok!(Dex::create_pool(coin2));

    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(20000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(1000) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));

    let exchange_out = 1;

    assert_noop!(
      Dex::swap_tokens_for_exact_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin1, coin2],
        exchange_out, // amount_out
        50,           // amount_in_max just greater than slippage.
        user,
      ),
      Error::<Test>::ProvidedMaximumNotSufficientForSwap
    );
  });
}

#[test]
fn swap_exact_tokens_for_tokens_in_multi_hops() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Dai;
    let coin3 = Coin::Monero;

    assert_ok!(Dex::create_pool(coin2));
    assert_ok!(Dex::create_pool(coin3));

    let base1 = 10000;
    let base2 = 10000;
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(base1 * 2) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(base2) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin3, amount: Amount(base2) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;
    let liquidity3 = 2000;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));
    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin3,
      liquidity3,
      liquidity1,
      1,
      1,
      user,
    ));

    let input_amount = 500;
    let expect_out2 = Dex::get_amount_out(input_amount, liquidity2, liquidity1).ok().unwrap();
    let expect_out3 = Dex::get_amount_out(expect_out2, liquidity1, liquidity3).ok().unwrap();

    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin1],
        input_amount,
        80,
        user,
      ),
      Error::<Test>::InvalidPath
    );

    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin2, coin1, coin2],
        input_amount,
        80,
        user,
      ),
      Error::<Test>::NonUniquePath
    );

    assert_ok!(Dex::swap_exact_tokens_for_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin2, coin1, coin3],
      input_amount, // amount_in
      80,           // amount_out_min
      user,
    ));

    let pool_id1 = Dex::get_pool_id(coin1, coin2).unwrap();
    let pool_id2 = Dex::get_pool_id(coin1, coin3).unwrap();
    let pallet_account1 = Dex::get_pool_account(pool_id1);
    let pallet_account2 = Dex::get_pool_account(pool_id2);

    assert_eq!(balance(user, coin2), base2 - liquidity2 - input_amount);
    assert_eq!(balance(pallet_account1, coin2), liquidity2 + input_amount);
    assert_eq!(balance(pallet_account1, coin1), liquidity1 - expect_out2);
    assert_eq!(balance(pallet_account2, coin1), liquidity1 + expect_out2);
    assert_eq!(balance(pallet_account2, coin3), liquidity3 - expect_out3);
    assert_eq!(balance(user, coin3), 10000 - liquidity3 + expect_out3);
  });
}

#[test]
fn swap_tokens_for_exact_tokens_in_multi_hops() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::native();
    let coin2 = Coin::Bitcoin;
    let coin3 = Coin::Ether;

    assert_ok!(Dex::create_pool(coin2));
    assert_ok!(Dex::create_pool(coin3));

    let base1 = 10000;
    let base2 = 10000;
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(base1 * 2) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(base2) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin3, amount: Amount(base2) }));

    let liquidity1 = 10000;
    let liquidity2 = 200;
    let liquidity3 = 2000;

    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin2,
      liquidity2,
      liquidity1,
      1,
      1,
      user,
    ));
    assert_ok!(Dex::add_liquidity(
      RuntimeOrigin::signed(user),
      coin3,
      liquidity3,
      liquidity1,
      1,
      1,
      user,
    ));

    let exchange_out3 = 100;
    let expect_in2 = Dex::get_amount_in(exchange_out3, liquidity1, liquidity3).ok().unwrap();
    let expect_in1 = Dex::get_amount_in(expect_in2, liquidity2, liquidity1).ok().unwrap();

    assert_ok!(Dex::swap_tokens_for_exact_tokens(
      RuntimeOrigin::signed(user),
      bvec![coin2, coin1, coin3],
      exchange_out3, // amount_out
      1000,          // amount_in_max
      user,
    ));

    let pool_id1 = Dex::get_pool_id(coin1, coin2).unwrap();
    let pool_id2 = Dex::get_pool_id(coin1, coin3).unwrap();
    let pallet_account1 = Dex::get_pool_account(pool_id1);
    let pallet_account2 = Dex::get_pool_account(pool_id2);

    assert_eq!(balance(user, coin2), base2 - liquidity2 - expect_in1);
    assert_eq!(balance(pallet_account1, coin1), liquidity1 - expect_in2);
    assert_eq!(balance(pallet_account1, coin2), liquidity2 + expect_in1);
    assert_eq!(balance(pallet_account2, coin1), liquidity1 + expect_in2);
    assert_eq!(balance(pallet_account2, coin3), liquidity3 - exchange_out3);
    assert_eq!(balance(user, coin3), 10000 - liquidity3 + exchange_out3);
  });
}

#[test]
fn can_not_swap_same_coin() {
  new_test_ext().execute_with(|| {
    let user = system_address(b"user1").into();
    let coin1 = Coin::Dai;
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(1000) }));

    let exchange_amount = 10;
    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![coin1, coin1],
        exchange_amount,
        1,
        user,
      ),
      Error::<Test>::PoolNotFound
    );

    assert_noop!(
      Dex::swap_exact_tokens_for_tokens(
        RuntimeOrigin::signed(user),
        bvec![Coin::native(), Coin::native()],
        exchange_amount,
        1,
        user,
      ),
      Error::<Test>::EqualCoins
    );
  });
}

#[test]
fn validate_pool_id_sorting() {
  new_test_ext().execute_with(|| {
    // Serai < Bitcoin < Ether < Dai < Monero.
    // coin1 <= coin2 for this test to pass.
    let native = Coin::native();
    let coin1 = Coin::Bitcoin;
    let coin2 = Coin::Monero;
    assert_eq!(Dex::get_pool_id(native, coin2).unwrap(), coin2);
    assert_eq!(Dex::get_pool_id(coin2, native).unwrap(), coin2);
    assert!(matches!(Dex::get_pool_id(native, native), Err(Error::<Test>::EqualCoins)));
    assert!(matches!(Dex::get_pool_id(coin2, coin1), Err(Error::<Test>::PoolNotFound)));
    assert!(coin2 > coin1);
    assert!(coin1 <= coin1);
    assert_eq!(coin1, coin1);
    assert!(native < coin1);
  });
}

#[test]
fn cannot_block_pool_creation() {
  new_test_ext().execute_with(|| {
    // User 1 is the pool creator
    let user = system_address(b"user1").into();
    // User 2 is the attacker
    let attacker = system_address(b"attacker").into();

    assert_ok!(CoinsPallet::<Test>::mint(
      attacker,
      Balance { coin: Coin::native(), amount: Amount(10000) }
    ));

    // The target pool the user wants to create is Native <=> Coin(2)
    let coin1 = Coin::native();
    let coin2 = Coin::Ether;

    // Attacker computes the still non-existing pool account for the target pair
    let pool_account = Dex::get_pool_account(Dex::get_pool_id(coin2, coin1).unwrap());
    // And transfers 1 to that pool account
    assert_ok!(CoinsPallet::<Test>::transfer_internal(
      attacker,
      pool_account,
      Balance { coin: Coin::native(), amount: Amount(1) }
    ));
    // Then, the attacker creates 14 tokens and sends one of each to the pool account
    // skip the coin1 and coin2 coins.
    for coin in coins().into_iter().filter(|c| (*c != coin1 && *c != coin2)) {
      assert_ok!(CoinsPallet::<Test>::mint(attacker, Balance { coin, amount: Amount(1000) }));
      assert_ok!(CoinsPallet::<Test>::transfer_internal(
        attacker,
        pool_account,
        Balance { coin, amount: Amount(1) }
      ));
    }

    // User can still create the pool
    assert_ok!(Dex::create_pool(coin2));

    // User has to transfer one Coin(2) token to the pool account (otherwise add_liquidity will
    // fail with `CoinTwoDepositDidNotMeetMinimum`), also transfer native token for the same error.
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin1, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::mint(user, Balance { coin: coin2, amount: Amount(10000) }));
    assert_ok!(CoinsPallet::<Test>::transfer_internal(
      user,
      pool_account,
      Balance { coin: coin2, amount: Amount(1) }
    ));
    assert_ok!(CoinsPallet::<Test>::transfer_internal(
      user,
      pool_account,
      Balance { coin: coin1, amount: Amount(100) }
    ));

    // add_liquidity shouldn't fail because of the number of consumers
    assert_ok!(Dex::add_liquidity(RuntimeOrigin::signed(user), coin2, 100, 9900, 10, 9900, user,));
  });
}

#[test]
fn test_median_price() {
  new_test_ext().execute_with(|| {
    use rand_core::{RngCore, OsRng};

    let mut prices = vec![];
    for i in 0 .. 100 {
      // Randomly use an active number
      if (i != 0) && (OsRng.next_u64() % u64::from(MEDIAN_PRICE_WINDOW_LENGTH / 3) == 0) {
        let old_index = usize::try_from(
          OsRng.next_u64() %
            u64::from(MEDIAN_PRICE_WINDOW_LENGTH) %
            u64::try_from(prices.len()).unwrap(),
        )
        .unwrap();
        let window_base = prices.len().saturating_sub(MEDIAN_PRICE_WINDOW_LENGTH.into());
        prices.push(prices[window_base + old_index]);
      } else {
        prices.push(OsRng.next_u64());
      }
    }
    let coin = Coin::Bitcoin;

    assert!(prices.len() >= (2 * usize::from(MEDIAN_PRICE_WINDOW_LENGTH)));
    for i in 0 .. prices.len() {
      let price = Amount(prices[i]);

      let n = BlockNumberFor::<Test>::from(u32::try_from(i).unwrap());
      SpotPriceForBlock::<Test>::set(n, coin, Some(price));
      Dex::insert_into_median(coin, price);
      if SpotPricesLength::<Test>::get(coin).unwrap() > MEDIAN_PRICE_WINDOW_LENGTH {
        let old = n - u64::from(MEDIAN_PRICE_WINDOW_LENGTH);
        let old_price = SpotPriceForBlock::<Test>::get(old, coin).unwrap();
        SpotPriceForBlock::<Test>::remove(old, coin);
        Dex::remove_from_median(coin, old_price);
      }

      // get the current window (cloning so our sort doesn't affect the original array)
      let window_base = (i + 1).saturating_sub(MEDIAN_PRICE_WINDOW_LENGTH.into());
      let mut window = Vec::from(&prices[window_base ..= i]);
      assert!(window.len() <= MEDIAN_PRICE_WINDOW_LENGTH.into());

      // get the median
      window.sort();
      let median_index = window.len() / 2;
      assert_eq!(Dex::median_price(coin).unwrap(), Amount(window[median_index]));
    }
  });
}
