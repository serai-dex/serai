#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::Encode;

use sp_io::hashing::blake2_256;
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
  use sp_runtime::traits::Zero;
  use sp_core::sr25519::Public;

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
    Batch { network: NetworkId, id: u32, block: BlockHash, instructions_hash: [u8; 32] },
    InstructionFailure { network: NetworkId, id: u32, index: u32 },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  // The ID of the last executed Batch for a network.
  #[pallet::storage]
  #[pallet::getter(fn batches)]
  pub(crate) type LastBatch<T: Config> = StorageMap<_, Blake2_256, NetworkId, u32, OptionQuery>;

  // The last Serai block in which this validator set included a batch
  #[pallet::storage]
  #[pallet::getter(fn last_batch_block)]
  pub(crate) type LastBatchBlock<T: Config> =
    StorageMap<_, Blake2_256, NetworkId, BlockNumberFor<T>, OptionQuery>;

  // The latest block a network has acknowledged as finalized
  #[pallet::storage]
  #[pallet::getter(fn latest_network_block)]
  pub(crate) type LatestNetworkBlock<T: Config> =
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

  fn key_for_network<T: Config>(network: NetworkId) -> Result<Public, InvalidTransaction> {
    // TODO: Get the latest session
    let session = Session(0);

    let mut set = ValidatorSet { session, network };
    // TODO: If this session just set their keys, it'll invalidate any batches in the mempool
    // Should there be a transitory period/future-set cut off?
    if let Some(keys) = ValidatorSets::<T>::keys(set) {
      Ok(keys.0)
    } else {
      // If this set hasn't set their keys yet, use the previous set's
      if set.session.0 == 0 {
        // Since there haven't been any keys set, no signature can legitimately exist
        Err(InvalidTransaction::BadProof)?;
      }
      set.session.0 -= 1;

      if let Some(keys) = ValidatorSets::<T>::keys(set) {
        Ok(keys.0)
      } else {
        Err(InvalidTransaction::BadProof)?
      }
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      let batch = batch.batch;

      // TODO: Test validate_unsigned is actually called prior to execution, which is required for
      // this to be safe
      LastBatchBlock::<T>::insert(batch.network, frame_system::Pallet::<T>::block_number());

      LastBatch::<T>::insert(batch.network, batch.id);
      LatestNetworkBlock::<T>::insert(batch.network, batch.block);
      Self::deposit_event(Event::Batch {
        network: batch.network,
        id: batch.id,
        block: batch.block,
        instructions_hash: blake2_256(&batch.instructions.encode()),
      });
      for (i, instruction) in batch.instructions.into_iter().enumerate() {
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
      let key = key_for_network::<T>(network)?;

      // verify the batch size
      // TODO: Merge this encode with the one done by batch_message
      if batch.batch.encode().len() > MAX_BATCH_SIZE {
        Err(InvalidTransaction::ExhaustsResources)?;
      }

      // verify the signature
      if !key.verify(&batch_message(&batch.batch), &batch.signature) {
        Err(InvalidTransaction::BadProof)?;
      }

      // check that this validator set isn't publishing a batch more than once per block
      let current_block = <frame_system::Pallet<T>>::block_number();
      let last_block = LastBatchBlock::<T>::get(network).unwrap_or(Zero::zero());
      if last_block >= current_block {
        Err(InvalidTransaction::Future)?;
      }

      // Verify the batch is sequential
      // LastBatch has the last ID set. The next ID should be it + 1
      // If there's no ID, the next ID should be 0
      let expected = LastBatch::<T>::get(network).map_or(0, |prev| prev + 1);
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
