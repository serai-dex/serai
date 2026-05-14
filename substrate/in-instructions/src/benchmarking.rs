#[allow(clippy::disallowed_methods, clippy::float_arithmetic)]
#[frame_benchmarking::v2::benchmarks(
  where <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>
)]
mod benchmarks {
  use sp_core::Encode as _;
  use serai_abi::{
    primitives::{
      network_id::*, validator_sets::*, coin::*, balance::*, address::*, crypto::*, instructions::*,
    },
    TransactionContext as _,
  };

  use frame_benchmarking::impl_test_function;

  use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance};

  use crate::{Config, Pallet, Call};

  #[benchmark]
  fn execute_batch() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);

    // 'Initialize' the Bitcoin liquidity pool
    serai_coins_pallet::Pallet::<T, LiquidityTokensInstance>::mint(
      SeraiAddress([0; 32]),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(10_000_000) },
    )
    .unwrap();
    serai_coins_pallet::Pallet::<T, CoinsInstance>::mint(
      serai_abi::dex::address(ExternalCoin::Bitcoin),
      Balance { coin: Coin::Serai, amount: Amount(10_000_000) },
    )
    .unwrap();

    // Mark all networks as having achieved economic security so we can add liquidity
    for network in ExternalNetworkId::all() {
      sp_io::storage::set(
        &(sp_core::twox_128(b"ValidatorSets"), sp_core::twox_128(b"CurrentSession"), network)
          .encode(),
        &Session(0).encode(),
      );

      sp_io::storage::set(
        &(
          sp_core::twox_128(b"EconomicSecurity"),
          sp_core::twox_128(b"AchievedEconomicSecurity"),
          network,
        )
          .encode(),
        &().encode(),
      );
    }

    // Set the oraclization key for the `Batch` to the identity to make the signature trivial
    sp_io::storage::set(
      &(
        sp_core::twox_128(b"ValidatorSets"),
        sp_core::twox_128(b"OraclizationKeys"),
        ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) },
      )
        .encode(),
      &Public([0; 32]).encode(),
    );

    /*
      Create a `Batch` entirely full of `SwapAndAddLiquidity` `InInstruction`s.

      Ignoring the pre-Economic Security-only `InInstruction`s (`GenesisLiquidity`, which shouldn't
      be the heaviest, and `SwapToStakedSri`, which is likely the heaviest but isn't forever), the
      remaining `InInstruction`s are:
      - `TransferWithSwap`
      - `Transfer`
      - `SwapAndAddLiquidity`
      - `Swap`
      - `SwapOut`
      where `SwapAndAddLiquidity` should quite apparenly be the heaviest, the only potential other
      candidate being `SwapOut`.

      One could program a weight dynamic to the actual instructions within the `Batch`, instead of
      simulating the worst-case `Batch` and going from there. Such effort is undergone currently
      but is kept in mind.
    */

    let in_instruction = InInstructionWithBalance {
      instruction: InInstruction::SwapAndAddLiquidity {
        address: SeraiAddress([0xaa; 32]),
        external_coin_liquidity: Amount(10),
        sri_minimum: Amount(0),
        sri_for_fees: Amount(1),
      },
      balance: ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(500) },
    };

    let mut batch = Batch::new(ExternalNetworkId::Bitcoin, 0, [0xbb; 32].into());
    while batch.push_instruction(in_instruction.clone()).is_ok() {}

    let mut signature = [0; 64];
    signature[63] = 1 << 7;
    let signature = Signature::Ristretto(RistrettoSignature(signature));

    let batch = SignedBatch { batch, signature };

    // We benchmark both the non-trivial `ValidateUnsigned::pre_dispatch` _and_ the execution
    #[block]
    {
      <Pallet<T> as frame_support::sp_runtime::traits::ValidateUnsigned>::pre_dispatch(
        &Call::execute_batch { batch: batch.clone() },
      )
      .unwrap();
      Pallet::<T>::execute_batch(T::RuntimeOrigin::from(None), batch).unwrap();
    }
  }

  frame_benchmarking::impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::Test
  );
}
