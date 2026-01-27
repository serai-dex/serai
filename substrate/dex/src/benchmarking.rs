#[allow(clippy::float_arithmetic)]
#[frame_benchmarking::v2::benchmarks(
  where <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>
)]
mod benchmarks {
  use serai_abi::{
    primitives::{coin::*, balance::*, address::*},
    TransactionContext as _,
  };

  use frame_benchmarking::impl_test_function;

  use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance};

  use crate::{Config, Pallet, Call};

  const ALICE: SeraiAddress = SeraiAddress([0xaa; 32]);
  const BOB: SeraiAddress = SeraiAddress([0xbb; 32]);

  #[benchmark]
  fn add_liquidity() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();

    // Initialize the pool, so we benchmark adding liquidity to an initialized pool
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Bitcoin,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();

    #[extrinsic_call]
    _(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Bitcoin,
      Amount(400),
      Amount(400),
      Amount(1),
      Amount(1),
    );
  }

  #[benchmark]
  fn transfer_liquidity() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    serai_coins_pallet::Pallet::<T, LiquidityTokensInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();

    #[extrinsic_call]
    _(
      T::RuntimeOrigin::from(Some(ALICE)),
      BOB,
      ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(1_000_000) },
    );
  }

  #[benchmark]
  fn remove_liquidity() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Bitcoin,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();

    #[extrinsic_call]
    _(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(400) },
      Amount(1),
      Amount(1),
    );
  }

  #[benchmark]
  fn swap(r: Linear<1, 2>) {
    let route_len = r;
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Bitcoin,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Ether.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Ether,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();

    let coins_to_swap = Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) };
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(BOB, coins_to_swap).unwrap();
    let minimum_to_receive = if route_len == 1 {
      Balance { coin: Coin::Serai, amount: Amount(1) }
    } else {
      Balance { coin: ExternalCoin::Ether.into(), amount: Amount(1) }
    };

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(BOB)), coins_to_swap, minimum_to_receive);
  }

  #[benchmark]
  fn swap_for(r: Linear<1, 2>) {
    let route_len = r;
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Bitcoin,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      ALICE,
      Balance { coin: ExternalCoin::Ether.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    Pallet::<T>::add_liquidity(
      T::RuntimeOrigin::from(Some(ALICE)),
      ExternalCoin::Ether,
      Amount(1_000_000),
      Amount(1_000_000),
      Amount(0),
      Amount(0),
    )
    .unwrap();

    let maximum_to_swap =
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(100_000_000) };
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(BOB, maximum_to_swap).unwrap();
    let coins_to_receive = if route_len == 1 {
      Balance { coin: Coin::Serai, amount: Amount(100) }
    } else {
      Balance { coin: ExternalCoin::Ether.into(), amount: Amount(100) }
    };

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(BOB)), coins_to_receive, maximum_to_swap);
  }

  frame_benchmarking::impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::Test
  );
}
