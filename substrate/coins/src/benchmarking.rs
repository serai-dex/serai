#[allow(clippy::disallowed_methods, clippy::float_arithmetic)]
#[frame_benchmarking::v2::instance_benchmarks(
  where <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>
)]
mod benchmarks {
  use alloc::vec;

  use serai_abi::{
    primitives::{coin::*, balance::*, address::*, instructions::*},
    TransactionContext as _,
  };

  use frame_benchmarking::impl_test_function;

  use crate::{Config, Pallet, Call};

  const ALICE: SeraiAddress = SeraiAddress([0xaa; 32]);
  const BOB: SeraiAddress = SeraiAddress([0xbb; 32]);
  const TRANSFER: ExternalBalance =
    ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(10) };

  #[benchmark]
  fn transfer() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    Pallet::<T, I>::mint(ALICE, TRANSFER.into()).unwrap();

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), BOB, TRANSFER.into());
  }

  #[benchmark]
  fn burn() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    Pallet::<T, I>::mint(ALICE, TRANSFER.into()).unwrap();

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), TRANSFER.into());
  }

  #[benchmark]
  fn burn_with_instruction() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    Pallet::<T, I>::mint(ALICE, TRANSFER.into()).unwrap();

    let instruction = OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(
        ExternalAddress::try_from(vec![0xff; usize::try_from(ExternalAddress::MAX_SIZE).unwrap()])
          .unwrap(),
      ),
      balance: TRANSFER,
    };

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), instruction);
  }

  #[cfg(test)]
  type Coins<T> = Pallet<T, crate::CoinsInstance>;
  frame_benchmarking::impl_benchmark_test_suite!(
    Coins,
    crate::tests::new_test_ext(vec![]),
    crate::tests::Test
  );
}
