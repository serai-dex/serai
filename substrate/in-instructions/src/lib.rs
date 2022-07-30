#![cfg_attr(not(feature = "std"), no_std)]

use scale::Encode;
#[cfg(feature = "std")]
use scale::Decode;

use sp_inherents::{InherentData, InherentIdentifier, IsFatalError};

pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"ininstrs";
// Amount of blocks to delay creating an inherent with a certain batch of transactions to increase
// the odds of synchrony
const DELAY: u32 = 2;

#[derive(Clone, PartialEq, Eq, Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode, scale_info::TypeInfo))]
pub struct InInstruction {
  destination: [u8; 32],
  amount: u64,
  data: Vec<u8>,
}

type Batch = Vec<InInstruction>;
type Batches = Vec<Batch>;
type Coins = Vec<Batches>;

// Block we learned of it, instructions
type TimedBatch = (u32, Batch);
type PendingBatches = Vec<TimedBatch>;
type PendingCoins = Vec<PendingBatches>;

#[derive(Encode, sp_runtime::RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode, thiserror::Error))]
pub enum InherentError {
  #[cfg_attr(feature = "std", error("unrecognized call"))]
  UnrecognizedCall,
  #[cfg_attr(feature = "std", error("inherent has {0} coins despite us having {1}"))]
  UnrecognizedCoins(u32, u32),
  #[cfg_attr(feature = "std", error("coin {0} has {1} more batches than we do"))]
  UnrecognizedBatch(u16, u32),
  #[cfg_attr(feature = "std", error("coin {0} has an invalid batch"))]
  InvalidBatch(u16),
}

impl IsFatalError for InherentError {
  fn is_fatal_error(&self) -> bool {
    true
  }
}

#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  #[pallet::config]
  pub trait Config: frame_system::Config {}

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  pub(super) type ExecutedBatches<T: Config> = StorageValue<_, bool, ValueQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(_: BlockNumberFor<T>) -> Weight {
      0
    }

    fn on_finalize(_: BlockNumberFor<T>) {
      ExecutedBatches::<T>::take();
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::weight((0, DispatchClass::Mandatory))] // TODO
    pub fn execute(origin: OriginFor<T>, coins: Coins) -> DispatchResult {
      ensure_none(origin)?;
      assert!(!ExecutedBatches::<T>::exists());
      ExecutedBatches::<T>::put(true);

      // TODO: EXECUTE

      Ok(())
    }
  }

  #[pallet::inherent]
  impl<T: Config> ProvideInherent for Pallet<T> {
    type Call = Call<T>;
    type Error = InherentError;
    const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

    fn create_inherent(data: &InherentData) -> Option<Self::Call> {
      let pending = data.get_data::<PendingCoins>(&INHERENT_IDENTIFIER).unwrap().unwrap();
      let mut coins = Coins::new();

      let mut any = false;
      for (coin, batches) in pending.iter().enumerate() {
        coins.push(Batches::new());
        for batch in batches {
          // If this batch has been queued for the delay period, propose it
          let current_block = 1; // TODO
          if (batch.0 + DELAY) <= current_block {
            coins[coin].push(batch.1.clone());
            any = true;
          }
        }
      }

      Some(Call::execute { coins }).filter(|_| any)
    }

    fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
      let sealed = false; // TODO
      if sealed {
        return Ok(());
      }

      let pending = data.get_data::<PendingCoins>(&INHERENT_IDENTIFIER).unwrap().unwrap();
      let coins = match call {
        Call::execute { ref coins } => coins,
        _ => Err(InherentError::UnrecognizedCall)?,
      };

      if coins.len() > pending.len() {
        Err(InherentError::UnrecognizedCoins(
          coins.len().try_into().unwrap(),
          pending.len().try_into().unwrap(),
        ))?;
      }

      for (coin, (batches, pending)) in coins.iter().zip(&pending).enumerate() {
        let coin = coin.try_into().unwrap();
        if batches.len() > pending.len() {
          Err(InherentError::UnrecognizedBatch(
            coin,
            (batches.len() - pending.len()).try_into().unwrap(),
          ))?;
        }

        for b in 0 .. batches.len() {
          if batches[b] != pending[b].1 {
            Err(InherentError::InvalidBatch(coin))?;
          }
        }
      }

      Ok(())
    }

    fn is_inherent(call: &Self::Call) -> bool {
      matches!(call, Call::execute { .. })
    }
  }
}
