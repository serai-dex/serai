#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::Encode;

use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockHash, NetworkId};

pub use in_instructions_primitives as primitives;
use primitives::*;

#[derive(Clone, Copy, Encode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(scale::Decode, thiserror::Error))]
pub enum PalletError {
  #[cfg_attr(feature = "std", error("batch for unrecognized network"))]
  UnrecognizedNetwork,
  #[cfg_attr(feature = "std", error("invalid signature for batch"))]
  InvalidSignature,
}

#[frame_support::pallet]
pub mod pallet {
  use sp_application_crypto::RuntimePublic;

  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use tokens_pallet::{Config as TokensConfig, Pallet as Tokens};
  use validator_sets_pallet::{
    primitives::{Session, ValidatorSet},
    Config as ValidatorSetsConfig, Pallet as ValidatorSets,
  };

  use super::*;

  #[pallet::config]
  pub trait Config: frame_system::Config + ValidatorSetsConfig + TokensConfig {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch { network: NetworkId, id: u32, block: BlockHash },
    InstructionFailure { network: NetworkId, id: u32, index: u32 },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  // The amount of batches a network has issued, which is also the ID to use for the next batch
  #[pallet::storage]
  #[pallet::getter(fn batches)]
  pub(crate) type Batches<T: Config> = StorageMap<_, Blake2_256, NetworkId, u32, OptionQuery>;

  // The latest block a network has acknowledged as finalized
  #[pallet::storage]
  #[pallet::getter(fn last_block)]
  pub(crate) type LatestBlock<T: Config> =
    StorageMap<_, Blake2_256, NetworkId, BlockHash, OptionQuery>;

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
      LatestBlock::<T>::insert(batch.network, batch.block);
      Self::deposit_event(Event::Batch {
        network: batch.network,
        id: batch.id,
        block: batch.block,
      });
      for (i, instruction) in batch.instructions.drain(..).enumerate() {
        // TODO: Check this balance's coin belongs to this network
        // If they don't, the validator set should be completely slashed, without question

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
        Call::__Ignore(_, _) => unreachable!(),
      };

      let network = batch.batch.network;

      // TODO: Get the latest session
      let session = Session(0);

      let mut set = ValidatorSet { session, network };
      // TODO: If this session just set their keys, it'll invalidate anything in the mempool
      // Should there be a transitory period/future-set cut off?
      let key = if let Some(keys) = ValidatorSets::<T>::keys(set) {
        keys.0
      } else {
        // If this set hasn't set their keys yet, use the previous set's
        if set.session.0 == 0 {
          Err(InvalidTransaction::BadProof)?;
        }
        set.session.0 -= 1;

        if let Some(keys) = ValidatorSets::<T>::keys(set) {
          keys.0
        } else {
          Err(InvalidTransaction::BadProof)?
        }
      };

      if !key.verify(&batch_message(&batch.batch), &batch.signature) {
        Err(InvalidTransaction::BadProof)?;
      }

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
