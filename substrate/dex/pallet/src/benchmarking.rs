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

//! Dex pallet benchmarking.

use super::*;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_support::{assert_ok, storage::bounded_vec::BoundedVec};
use frame_system::RawOrigin as SystemOrigin;
use sp_core::Get;
use sp_runtime::traits::{Bounded, StaticLookup};
use sp_std::{ops::Div, prelude::*};

use crate::Pallet as Dex;

const INITIAL_COIN_BALANCE: u64 = 1_000_000_000;
type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;
type BalanceOf<T> =
  <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

fn get_lp_token_id<T: Config>() -> T::PoolCoinId
where
  T::PoolCoinId: Into<u32>,
{
  let next_id: u32 = Dex::<T>::get_next_pool_coin_id().into();
  (next_id - 1).into()
}

fn create_coin<T: Config>(coin: &T::MultiCoinId) -> (T::AccountId, AccountIdLookupOf<T>)
where
  T::CoinBalance: From<u64>,
  T::Currency: Currency<T::AccountId>,
  T::Coins: Coins<T::AccountId>,
{
  let caller: T::AccountId = whitelisted_caller();
  let caller_lookup = T::Lookup::unlookup(caller.clone());
  if let MultiCoinIdConversionResult::Converted(coin_id) =
    T::MultiCoinIdConverter::try_convert(coin)
  {
    assert_ok!(T::Currency::mint(&caller, BalanceOf::<T>::max_value().div(1000u32.into())));
    assert_ok!(T::Coins::mint(coin_id, &caller, INITIAL_COIN_BALANCE.into()));
  }
  (caller, caller_lookup)
}

fn create_coin_and_pool<T: Config>(
  coin1: &T::MultiCoinId,
  coin2: &T::MultiCoinId,
) -> (T::PoolCoinId, T::AccountId, AccountIdLookupOf<T>)
where
  T::CoinBalance: From<u64>,
  T::Currency: Currency<T::AccountId>,
  T::Coins: Coins<T::AccountId>,
  T::PoolCoinId: Into<u32>,
{
  let (_, _) = create_coin::<T>(coin1);
  let (caller, caller_lookup) = create_coin::<T>(coin2);

  assert_ok!(Dex::<T>::create_pool(
    SystemOrigin::Signed(caller.clone()).into(),
    coin1.clone(),
    coin2.clone()
  ));
  let lp_token = get_lp_token_id::<T>();

  (lp_token, caller, caller_lookup)
}

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
  let events = frame_system::Pallet::<T>::events();
  let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
  // compare to the last event record
  let frame_system::EventRecord { event, .. } = &events[events.len() - 1];
  assert_eq!(event, &system_event);
}

benchmarks! {
  where_clause {
    where
      T::CoinBalance: From<u64> + Into<u64>,
      T::Currency: Currency<T::AccountId>,
      T::Balance: From<u64> + Into<u64>,
      T::Coins: Coins<T::AccountId>,
      T::PoolCoinId: Into<u32>,
  }

  create_pool {
    let coin1 = T::MultiCoinIdConverter::get_native();
    let coin2: T::MultiCoinId = T::BenchmarkHelper::coin_id(0).into();
    let (caller, _) = create_coin::<T>(&coin2);
  }: _(SystemOrigin::Signed(caller.clone()), coin1.clone(), coin2.clone())
  verify {
    let lp_token = get_lp_token_id::<T>();
    let pool_id = (coin1.clone(), coin2.clone());
    assert_last_event::<T>(Event::PoolCreated {
      creator: caller.clone(),
      pool_account: Dex::<T>::get_pool_account(&pool_id),
      pool_id,
      lp_token,
    }.into());
  }

  add_liquidity {
    let coin1 = T::MultiCoinIdConverter::get_native();
    let coin2: T::MultiCoinId = T::BenchmarkHelper::coin_id(0).into();
    let (lp_token, caller, _) = create_coin_and_pool::<T>(&coin1, &coin2);
    let ed: u64 = T::Currency::minimum_balance().into();
    let add_amount = 1000 + ed;
  }: _(
    SystemOrigin::Signed(caller.clone()),
    coin1.clone(),
    coin2.clone(),
    add_amount.into(),
    1000.into(),
    0.into(),
    0.into(),
    caller.clone()
  )
  verify {
    let pool_id = (coin1.clone(), coin2.clone());
    let lp_minted = Dex::<T>::calc_lp_amount_for_zero_supply(
      &add_amount.into(),
      &1000.into()
    ).unwrap().into();
    assert_eq!(
      T::PoolCoins::balance(lp_token, &caller),
      lp_minted.into()
    );
    assert_eq!(
      T::Currency::balance(&Dex::<T>::get_pool_account(&pool_id)),
      add_amount.into()
    );
    assert_eq!(
      T::Coins::balance(
        T::BenchmarkHelper::coin_id(0),
        &Dex::<T>::get_pool_account(&pool_id)
      ),
      1000.into()
    );
  }

  remove_liquidity {
    let coin1 = T::MultiCoinIdConverter::get_native();
    let coin2: T::MultiCoinId = T::BenchmarkHelper::coin_id(0).into();
    let (lp_token, caller, _) = create_coin_and_pool::<T>(&coin1, &coin2);
    let ed: u64 = T::Currency::minimum_balance().into();
    let add_amount = 100 * ed;
    let lp_minted = Dex::<T>::calc_lp_amount_for_zero_supply(
      &add_amount.into(),
      &1000.into()
    ).unwrap().into();
    let remove_lp_amount = lp_minted.checked_div(10).unwrap();

    Dex::<T>::add_liquidity(
      SystemOrigin::Signed(caller.clone()).into(),
      coin1.clone(),
      coin2.clone(),
      add_amount.into(),
      1000.into(),
      0.into(),
      0.into(),
      caller.clone(),
    )?;
    let total_supply =
      <T::PoolCoins as LiquidityTokens<T::AccountId>>::total_issuance(lp_token.clone());
  }: _(
    SystemOrigin::Signed(caller.clone()),
    coin1,
    coin2,
    remove_lp_amount.into(),
    0.into(),
    0.into(),
    caller.clone()
  )
  verify {
    let new_total_supply =
      <T::PoolCoins as LiquidityTokens<T::AccountId>>::total_issuance(lp_token.clone());
    assert_eq!(
      new_total_supply,
      total_supply - remove_lp_amount.into()
    );
  }

  swap_exact_tokens_for_tokens {
    let native = T::MultiCoinIdConverter::get_native();
    let coin1: T::MultiCoinId = T::BenchmarkHelper::coin_id(1).into();
    let coin2: T::MultiCoinId = T::BenchmarkHelper::coin_id(2).into();
    let (_, caller, _) = create_coin_and_pool::<T>(&native, &coin1);
    let (_, _) = create_coin::<T>(&coin2);
    let ed: u64 = T::Currency::minimum_balance().into();
    let ed_bump = 2u64;

    Dex::<T>::add_liquidity(
      SystemOrigin::Signed(caller.clone()).into(),
      native.clone(),
      coin1.clone(),
      // TODO: this call otherwise fails with `InsufficientLiquidityMinted`.
      // might be again related to their expectance on ed being > 1.
      (100 * (ed + ed_bump)).into(),
      200.into(),
      0.into(),
      0.into(),
      caller.clone(),
    )?;

    let path;
    let swap_amount;
    // if we only allow the native-coin pools, then the worst case scenario would be to swap
    // coin1-native-coin2
    if !T::AllowMultiCoinPools::get() {
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        native.clone(),
        coin2.clone()
      )?;
      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        native.clone(),
        coin2.clone(),
        (500 * ed).into(),
        1000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      path = vec![coin1.clone(), native.clone(), coin2.clone()];
      swap_amount = 100.into();
    } else {
      let coin3: T::MultiCoinId = T::BenchmarkHelper::coin_id(3).into();
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        coin1.clone(),
        coin2.clone()
      )?;
      let (_, _) = create_coin::<T>(&coin3);
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        coin2.clone(),
        coin3.clone()
      )?;

      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        coin1.clone(),
        coin2.clone(),
        200.into(),
        2000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        coin2.clone(),
        coin3.clone(),
        2000.into(),
        2000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      path = vec![native.clone(), coin1.clone(), coin2.clone(), coin3.clone()];
      swap_amount = (ed + ed_bump).into();
    }

    let path: BoundedVec<_, T::MaxSwapPathLength> = BoundedVec::try_from(path).unwrap();
    let native_balance = T::Currency::balance(&caller);
    let coin1_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(1), &caller);
  }: _(SystemOrigin::Signed(caller.clone()), path, swap_amount, 1.into(), caller.clone())
  verify {
    let ed_bump = 2u64;
    if !T::AllowMultiCoinPools::get() {
      let new_coin1_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(1), &caller);
      assert_eq!(new_coin1_balance, coin1_balance - 100.into());
    } else {
      let new_native_balance = T::Currency::balance(&caller);
      assert_eq!(new_native_balance, native_balance - (ed + ed_bump).into());
    }
  }

  swap_tokens_for_exact_tokens {
    let native = T::MultiCoinIdConverter::get_native();
    let coin1: T::MultiCoinId = T::BenchmarkHelper::coin_id(1).into();
    let coin2: T::MultiCoinId = T::BenchmarkHelper::coin_id(2).into();
    let (_, caller, _) = create_coin_and_pool::<T>(&native, &coin1);
    let (_, _) = create_coin::<T>(&coin2);
    let ed: u64 = T::Currency::minimum_balance().into();

    Dex::<T>::add_liquidity(
      SystemOrigin::Signed(caller.clone()).into(),
      native.clone(),
      coin1.clone(),
      (1000 * ed).into(),
      500.into(),
      0.into(),
      0.into(),
      caller.clone(),
    )?;

    // if we only allow the native-coin pools, then the worst case scenario would be to swap
    // coin1-native-coin2
    let path = if !T::AllowMultiCoinPools::get() {
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        native.clone(),
        coin2.clone()
      )?;
      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        native.clone(),
        coin2.clone(),
        (500 * ed).into(),
        1000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      vec![coin1.clone(), native.clone(), coin2.clone()]
    } else {
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        coin1.clone(),
        coin2.clone()
      )?;
      let coin3: T::MultiCoinId = T::BenchmarkHelper::coin_id(3).into();
      let (_, _) = create_coin::<T>(&coin3);
      Dex::<T>::create_pool(
        SystemOrigin::Signed(caller.clone()).into(),
        coin2.clone(),
        coin3.clone()
      )?;

      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        coin1.clone(),
        coin2.clone(),
        2000.into(),
        2000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      Dex::<T>::add_liquidity(
        SystemOrigin::Signed(caller.clone()).into(),
        coin2.clone(),
        coin3.clone(),
        2000.into(),
        2000.into(),
        0.into(),
        0.into(),
        caller.clone(),
      )?;
      vec![native.clone(), coin1.clone(), coin2.clone(), coin3.clone()]
    };

    let path: BoundedVec<_, T::MaxSwapPathLength> = BoundedVec::try_from(path).unwrap();
    let coin2_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(2), &caller);
    let coin3_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(3), &caller);
  }: _(
    SystemOrigin::Signed(caller.clone()),
    path.clone(),
    100.into(),
    (1000 * ed).into(),
    caller.clone()
  )
  verify {
    if !T::AllowMultiCoinPools::get() {
      let new_coin2_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(2), &caller);
      assert_eq!(new_coin2_balance, coin2_balance + 100.into());
    } else {
      let new_coin3_balance = T::Coins::balance(T::BenchmarkHelper::coin_id(3), &caller);
      assert_eq!(new_coin3_balance, coin3_balance + 100.into());
    }
  }

  impl_benchmark_test_suite!(Dex, crate::mock::new_test_ext(), crate::mock::Test);
}
