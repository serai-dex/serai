#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_std::vec::Vec;
use sp_inherents::{InherentIdentifier, IsFatalError};

use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockNumber, BlockHash, Coin};

pub use in_instructions_primitives as primitives;
use primitives::InInstruction;

pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"ininstrs";

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Batch {
  pub id: BlockHash,
  pub instructions: Vec<InInstruction>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Update {
  // Coin's latest block number
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
  #[cfg_attr(feature = "std", error("coin {0:?} has a different batch (ID {1:?})"))]
  DifferentBatch(Coin, BlockHash),
}

impl IsFatalError for InherentError {
  fn is_fatal_error(&self) -> bool {
    match self {
      InherentError::InvalidCall | InherentError::InvalidUpdateQuantity(..) => true,
      InherentError::UnrecognizedBlockNumber(..) => false,
      InherentError::InvalidBlockNumber(..) => true,
      InherentError::UnrecognizedBatches(..) => false,
      // One of our nodes is definitively wrong. If it's ours (signified by it passing consensus),
      // we should panic. If it's theirs, they should be slashed
      // Unfortunately, we can't return fatal here to trigger a slash as fatal should only be used
      // for undeniable, technical invalidity
      // TODO: Code a way in which this still triggers a slash vote
      InherentError::DifferentBatch(..) => false,
    }
  }
}

fn coin_from_index(index: usize) -> Coin {
  // Offset by 1 since Serai is the first coin, yet Serai doesn't have updates
  Coin::from(1 + u32::try_from(index).unwrap())
}

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use super::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<BlockNumber = u32> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch { coin: Coin, id: BlockHash },
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(crate) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  // Used to only allow one set of updates per block, preventing double updating
  #[pallet::storage]
  pub(crate) type Once<T: Config> = StorageValue<_, bool, ValueQuery>;
  // Latest block number agreed upon for a coin
  #[pallet::storage]
  #[pallet::getter(fn block_number)]
  pub(crate) type BlockNumbers<T: Config> =
    StorageMap<_, Blake2_256, Coin, BlockNumber, ValueQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(_: BlockNumberFor<T>) {
      Once::<T>::take();
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn update(origin: OriginFor<T>, updates: Updates) -> DispatchResult {
      ensure_none(origin)?;
      assert!(!Once::<T>::exists());
      Once::<T>::put(true);

      for (coin, update) in updates.iter().enumerate() {
        if let Some(update) = update {
          let coin = coin_from_index(coin);
          BlockNumbers::<T>::insert(coin, update.block_number);

          for batch in &update.batches {
            // TODO: EXECUTE
            Self::deposit_event(Event::Batch { coin, id: batch.id });
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
        .map(|updates| Call::update { updates })
    }

    // Assumes that only not yet handled batches are provided as inherent data
    fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
      // First unwrap is for the Result of fetching/decoding the Updates
      // Second unwrap is for the Option of if they exist
      let expected = data.get_data::<Updates>(&INHERENT_IDENTIFIER).unwrap().unwrap();
      // Match to be exhaustive
      let updates = match call {
        Call::update { ref updates } => updates,
        _ => Err(InherentError::InvalidCall)?,
      };

      // The block producer should've provided one update per coin
      // We, an honest node, did provide one update per coin
      // Accordingly, we should have the same amount of updates
      if updates.len() != expected.len() {
        Err(InherentError::InvalidUpdateQuantity(
          updates.len().try_into().unwrap(),
          expected.len().try_into().unwrap(),
        ))?;
      }

      // This zip is safe since we verified they're equally sized
      // This should be written as coins.zip(updates.iter().zip(&expected)), where coins is the
      // validator set's coins
      // That'd require having context on the validator set right now which isn't worth pulling in
      // right now, when we only have one validator set
      for (coin, both) in updates.iter().zip(&expected).enumerate() {
        let coin = coin_from_index(coin);
        match both {
          // Block producer claims there's an update for this coin, as do we
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

            for (batch, expected) in update.batches.iter().zip(&expected.batches) {
              if batch != expected {
                Err(InherentError::DifferentBatch(coin, batch.id))?;
              }
            }
          }

          // Block producer claims there's an update for this coin, yet we don't
          (Some(update), None) => {
            Err(InherentError::UnrecognizedBatches(coin, update.batches.len().try_into().unwrap()))?
          }

          // Block producer didn't include update for this coin
          (None, _) => (),
        };
      }

      Ok(())
    }

    fn is_inherent(_: &Self::Call) -> bool {
      true
    }
  }
}

pub use pallet::*;
