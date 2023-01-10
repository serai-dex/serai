#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode};

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_std::vec::Vec;
use sp_inherents::{InherentData, InherentIdentifier, IsFatalError};

#[cfg(feature = "std")]
pub mod provider;

pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"ininstrs";
// Amount of blocks to delay creating an inherent with a certain batch of transactions to increase
// the odds of synchrony
const DELAY: u32 = 2;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, sp_runtime::RuntimeDebug)]
pub struct InInstruction {
  pub destination: [u8; 32],
  pub amount: u64,
  pub data: Vec<u8>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, sp_runtime::RuntimeDebug)]
pub struct Coin<T> {
  // Coin's current height
  // Ideally, this would be the coin's current block hash, or a 32-byte hash of any global clock
  // We would be unable to validate those unless we can pass a HashMap with the inherent data
  pub height: u32,
  pub batches: Vec<T>,
}

// None if the current block producer isn't operating over this coin or otherwise failed to get
// data
pub(crate) type GenericCoins<T> = Vec<Option<Coin<T>>>;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, sp_runtime::RuntimeDebug)]
pub struct Batch {
  pub id: u32,
  pub instructions: Vec<InInstruction>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, sp_runtime::RuntimeDebug)]
pub struct PendingBatch {
  // Height this batch was initially reported at
  pub reported_at: u32,
  pub batch: Batch,
}

pub type Coins = GenericCoins<Batch>;
pub type PendingCoins = GenericCoins<PendingBatch>;

#[derive(Encode, sp_runtime::RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode, thiserror::Error))]
pub enum InherentError {
  #[cfg_attr(feature = "std", error("invalid call"))]
  InvalidCall,
  #[cfg_attr(feature = "std", error("inherent has {0} coins despite us having {1}"))]
  InvalidCoins(u32, u32),
  #[cfg_attr(feature = "std", error("inherent has height {0} despite us having {1}"))]
  UnrecognizedHeight(u32, u32),
  #[cfg_attr(feature = "std", error("inherent has height {0} which doesn't succeed {1}"))]
  InvalidHeight(u32, u32),
  #[cfg_attr(feature = "std", error("coin {0} has {1} more batches than we do"))]
  UnrecognizedBatch(u32, u32),
  #[cfg_attr(feature = "std", error("coin {0} has an invalid batch"))]
  InvalidBatch(u32),
  #[cfg_attr(feature = "std", error("coin {0} has a different batch (ID {1})"))]
  DifferentBatch(u32, u32),
}

impl IsFatalError for InherentError {
  fn is_fatal_error(&self) -> bool {
    match self {
      InherentError::InvalidCall | InherentError::InvalidCoins(..) => true,
      InherentError::UnrecognizedHeight(..) => false,
      InherentError::InvalidHeight(..) => true,
      InherentError::UnrecognizedBatch(..) => false,
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
    Batch(u32, u32),
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(crate) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  pub(crate) type Once<T: Config> = StorageValue<_, bool, ValueQuery>;
  #[pallet::storage]
  #[pallet::getter(fn height)]
  pub(crate) type Heights<T: Config> = StorageMap<_, Blake2_256, u32, u32, ValueQuery>;
  #[pallet::storage]
  #[pallet::getter(fn executed_batches)]
  pub(crate) type Executed<T: Config> = StorageMap<_, Blake2_256, u32, u32, ValueQuery>;

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
    pub fn execute(origin: OriginFor<T>, coins: Coins) -> DispatchResult {
      ensure_none(origin)?;
      assert!(!Once::<T>::exists());
      Once::<T>::put(true);

      for (c, coin) in coins.iter().enumerate() {
        if let Some(coin) = coin {
          let c = c.try_into().unwrap();
          Heights::<T>::insert(c, coin.height);

          for batch in &coin.batches {
            // TODO: EXECUTE
            Self::deposit_event(Event::Batch(c, batch.id));
            Executed::<T>::insert(c, batch.id + 1);
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
      let current_block = <frame_system::Pallet<T>>::block_number();

      data.get_data::<PendingCoins>(&INHERENT_IDENTIFIER).unwrap().map(|pending| Call::execute {
        coins: pending
          .iter()
          // Map each Option<Coin<PendingBatch>>
          .map(|coin| {
            // to an Option<Coin<Batch>>
            coin.clone().map(|coin| Coin {
              height: coin.height,
              // Only propose this batch if it's been queued for the delay period
              batches: coin
                .batches
                .iter()
                .filter_map(|batch| {
                  if (batch.reported_at + DELAY) <= current_block {
                    Some(batch.batch.clone())
                  } else {
                    None
                  }
                })
                .collect(),
            })
          })
          .collect(),
      })
    }

    fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
      let sealed = false; // TODO
      if sealed {
        return Ok(());
      }

      // Assumes that only not yet handled batches are provided as inherent data
      if let Some(pending) = data.get_data::<PendingCoins>(&INHERENT_IDENTIFIER).unwrap() {
        // Match to be exhaustive
        let coins = match call {
          Call::execute { ref coins } => coins,
          _ => Err(InherentError::InvalidCall)?,
        };

        if coins.len() != pending.len() {
          Err(InherentError::InvalidCoins(
            coins.len().try_into().unwrap(),
            pending.len().try_into().unwrap(),
          ))?;
        }

        for (c, both) in coins.iter().zip(&pending).enumerate() {
          let c = c.try_into().unwrap();
          match both {
            (Some(coin), Some(pending)) => {
              if coin.height > pending.height {
                Err(InherentError::UnrecognizedHeight(coin.height, pending.height))?;
              }

              let prev = Heights::<T>::get(c);
              if coin.height <= prev {
                Err(InherentError::InvalidHeight(coin.height, prev))?;
              }

              if coin.batches.len() > pending.batches.len() {
                Err(InherentError::UnrecognizedBatch(
                  c,
                  (coin.batches.len() - pending.batches.len()).try_into().unwrap(),
                ))?;
              }

              let mut last_executed = Executed::<T>::get(c);
              for (batch, pending) in coin.batches.iter().zip(&pending.batches) {
                if batch.id != last_executed {
                  Err(InherentError::InvalidBatch(c))?;
                }
                last_executed += 1;

                if *batch != pending.batch {
                  Err(InherentError::DifferentBatch(c, batch.id))?;
                }
              }
            }

            // TODO: Accept this if voted on by the validator set which validates this coin
            (Some(coin), None) => {
              Err(InherentError::UnrecognizedBatch(c, coin.batches.len().try_into().unwrap()))?
            }

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
