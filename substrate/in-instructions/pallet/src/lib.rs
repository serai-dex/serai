#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode};

use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockHash, NetworkId};

pub use in_instructions_primitives as primitives;
use primitives::{InInstruction, InInstructionWithBalance, SignedBatch};

#[derive(Clone, Copy, Encode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode, thiserror::Error))]
pub enum PalletError {
  #[cfg_attr(feature = "std", error("batch for unrecognized network"))]
  UnrecognizedNetwork,
  #[cfg_attr(feature = "std", error("invalid signature for batch"))]
  InvalidSignature,
}

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use tokens_pallet::{Config as TokensConfig, Pallet as Tokens};

  use super::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<BlockNumber = u64> + TokensConfig {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch { network: NetworkId, id: u32, block: BlockHash },
    InstructionFailure { network: NetworkId, id: u32, index: u32 },
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(crate) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  // Latest block number agreed upon for a coin
  #[pallet::storage]
  #[pallet::getter(fn batch)]
  pub(crate) type Batches<T: Config> = StorageMap<_, Blake2_256, NetworkId, u32, OptionQuery>;

  impl<T: Config> Pallet<T> {
    fn execute(instruction: InInstructionWithBalance) -> Result<(), ()> {
      match instruction.instruction {
        InInstruction::Transfer(address) => Tokens::<T>::mint(address, instruction.balance),
        _ => panic!("unsupported instruction"),
      }
      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      let mut batch = batch.batch;

      Batches::<T>::insert(batch.network, batch.id);
      Self::deposit_event(Event::Batch {
        network: batch.network,
        id: batch.id,
        block: batch.block,
      });
      for (i, instruction) in batch.instructions.drain(..).enumerate() {
        if Self::execute(instruction).is_err() {
          Self::deposit_event(Event::InstructionFailure {
            network: batch.network,
            id: batch.id,
            index: u32::try_from(i).unwrap(),
          });
        }
      }

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      let batch = match call {
        Call::execute_batch { ref batch } => batch,
        _ => Err(InvalidTransaction::Call)?,
      };

      let network = batch.batch.network;

      // TODO: Get the key for this network or Err(UnrecognizedNetwork)

      // TODO: Verify the signature or Err(InvalidSignature)

      // Verify the batch is sequential
      // Batches has the last ID set. The next ID should be it + 1
      // If there's no ID, the next ID should be 0
      let expected = Batches::<T>::get(network).map(|prev| prev + 1).unwrap_or(0);
      if batch.batch.id < expected {
        Err(InvalidTransaction::Stale)?;
      }
      if batch.batch.id > expected {
        Err(InvalidTransaction::Future)?;
      }

      ValidTransaction::with_tag_prefix("in-instructions")
        .and_provides((batch.batch.network, batch.batch.id))
        // Set a 10 block longevity, though this should be included in the next block
        .longevity(10)
        .propagate(true)
        .build()
    }
  }
}

pub use pallet::*;
