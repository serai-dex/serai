#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_std::vec::Vec;
use sp_inherents::{InherentData, InherentIdentifier, IsFatalError};

use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockNumber, Coin};

use in_instructions_primitives::InInstruction;

pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"ininstrs";

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Batch {
  pub id: u64,
  pub instructions: Vec<InInstruction>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Update {
  // Coin's latest block number
  // Ideally, this would be the coin's current block hash, or a 32-byte hash of any global clock
  // We would be unable to validate those unless we can pass a HashMap with the inherent data
  pub block_number: BlockNumber,
  pub batches: Vec<Batch>,
}

// None if the current block producer isn't operating over this coin or otherwise failed to get
// data
pub type Updates = Vec<Option<Update>>;

#[derive(Clone, Copy, Encode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode, thiserror::Error))]
pub enum InherentError {
  #[cfg_attr(feature = "std", error("invalid call"))]
  InvalidCall,
  #[cfg_attr(feature = "std", error("inherent has {0} updates despite us having {1} coins"))]
  InvalidUpdateQuantity(u32, u32),
  #[cfg_attr(
    feature = "std",
    error("inherent for coin {0:?} has block number {1:?} despite us having {2:?}")
  )]
  UnrecognizedBlockNumber(Coin, BlockNumber, BlockNumber),
  #[cfg_attr(
    feature = "std",
    error("inherent for coin {0:?} has block number {1:?} which doesn't succeed {2:?}")
  )]
  InvalidBlockNumber(Coin, BlockNumber, BlockNumber),
  #[cfg_attr(feature = "std", error("coin {0:?} has {1} more batches than we do"))]
  UnrecognizedBatches(Coin, u32),
  #[cfg_attr(feature = "std", error("coin {0:?} has an invalid batch"))]
  InvalidBatch(Coin),
  #[cfg_attr(feature = "std", error("coin {0:?} has a different batch (ID {1})"))]
  DifferentBatch(Coin, u64),
}

impl IsFatalError for InherentError {
  fn is_fatal_error(&self) -> bool {
    match self {
      InherentError::InvalidCall | InherentError::InvalidUpdateQuantity(..) => true,
      InherentError::UnrecognizedBlockNumber(..) => false,
      InherentError::InvalidBlockNumber(..) => true,
      InherentError::UnrecognizedBatches(..) => false,
      InherentError::InvalidBatch(..) => true,
      // One of our nodes is definitively wrong. If it's ours (signified by it passing consensus),
      // we should panic
      InherentError::DifferentBatch(..) => false,
    }
  }
}

#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<BlockNumber = u32> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch { coin: Coin, id: u64 },
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(crate) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  pub(crate) type Once<T: Config> = StorageValue<_, bool, ValueQuery>;
  #[pallet::storage]
  #[pallet::getter(fn block_number)]
  pub(crate) type BlockNumbers<T: Config> =
    StorageMap<_, Blake2_256, Coin, BlockNumber, ValueQuery>;
  #[pallet::storage]
  #[pallet::getter(fn executed_batches)]
  pub(crate) type NextBatch<T: Config> = StorageMap<_, Blake2_256, Coin, u64, ValueQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(_: BlockNumberFor<T>) {
      Once::<T>::take();
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Mandatory))] // TODO
    pub fn execute(origin: OriginFor<T>, updates: Updates) -> DispatchResult {
      ensure_none(origin)?;
      assert!(!Once::<T>::exists());
      Once::<T>::put(true);

      for (coin, update) in updates.iter().enumerate() {
        if let Some(update) = update {
          let coin = Coin::from(u32::try_from(coin).unwrap());
          BlockNumbers::<T>::insert(coin, update.block_number);

          for batch in &update.batches {
            // TODO: EXECUTE
            Self::deposit_event(Event::Batch { coin, id: batch.id });
            NextBatch::<T>::insert(coin, batch.id + 1);
          }
        }
      }

      Ok(())
    }
  }

  #[pallet::inherent]
  impl<T: Config> ProvideInherent for Pallet<T> {
    type Call = Call<T>;
    type Error = InherentError;
    const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

    fn create_inherent(data: &InherentData) -> Option<Self::Call> {
      data
        .get_data::<Updates>(&INHERENT_IDENTIFIER)
        .unwrap()
        .map(|updates| Call::execute { updates })
    }

    fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
      // Assumes that only not yet handled batches are provided as inherent data
      if let Some(expected) = data.get_data::<Updates>(&INHERENT_IDENTIFIER).unwrap() {
        // Match to be exhaustive
        let updates = match call {
          Call::execute { ref updates } => updates,
          _ => Err(InherentError::InvalidCall)?,
        };

        if updates.len() != expected.len() {
          Err(InherentError::InvalidUpdateQuantity(
            updates.len().try_into().unwrap(),
            expected.len().try_into().unwrap(),
          ))?;
        }

        for (coin, both) in updates.iter().zip(&expected).enumerate() {
          let coin = Coin::from(u32::try_from(coin).unwrap());
          match both {
            (Some(update), Some(expected)) => {
              if update.block_number.0 > expected.block_number.0 {
                Err(InherentError::UnrecognizedBlockNumber(
                  coin,
                  update.block_number,
                  expected.block_number,
                ))?;
              }

              let prev = BlockNumbers::<T>::get(coin);
              if update.block_number.0 <= prev.0 {
                Err(InherentError::InvalidBlockNumber(coin, update.block_number, prev))?;
              }

              if update.batches.len() > expected.batches.len() {
                Err(InherentError::UnrecognizedBatches(
                  coin,
                  (update.batches.len() - expected.batches.len()).try_into().unwrap(),
                ))?;
              }

              let mut next_batch = NextBatch::<T>::get(coin);
              for (batch, expected) in update.batches.iter().zip(&expected.batches) {
                if batch.id != next_batch {
                  Err(InherentError::InvalidBatch(coin))?;
                }
                next_batch += 1;

                if batch != expected {
                  Err(InherentError::DifferentBatch(coin, batch.id))?;
                }
              }
            }

            (Some(update), None) => Err(InherentError::UnrecognizedBatches(
              coin,
              update.batches.len().try_into().unwrap(),
            ))?,

            (None, _) => (),
          };
        }
      }

      Ok(())
    }

    fn is_inherent(_: &Self::Call) -> bool {
      true
    }
  }
}

pub use pallet::*;
