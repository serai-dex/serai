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

  use coins_pallet::{Config as CoinsConfig, Pallet as Coins};
  use validator_sets_pallet::{
    primitives::{Session, ValidatorSet},
    Config as ValidatorSetsConfig, Pallet as ValidatorSets,
  };

  use super::*;

  #[pallet::config]
  pub trait Config: frame_system::Config + ValidatorSetsConfig + CoinsConfig {
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
        InInstruction::Transfer(address) => {
          // TODO: pass balance directly here instead of coin and amount?
          // but coins pallet deals only with SubstrateAmount and Balance type has Amount type.
          Coins::<T>::mint(&address.into(), instruction.balance.coin, instruction.balance.amount.0)
            .map_err(|_| ())
        }
        _ => panic!("unsupported instruction"),
      }
    }
  }

  fn keys_for_network<T: Config>(
    network: NetworkId,
  ) -> Result<(Session, Option<Public>, Option<Public>), InvalidTransaction> {
    let session = ValidatorSets::<T>::session(network);
    let mut set = ValidatorSet { session, network };
    let latest = ValidatorSets::<T>::keys(set).map(|keys| keys.0);
    let prior = if set.session.0 != 0 {
      set.session.0 -= 1;
      ValidatorSets::<T>::keys(set).map(|keys| keys.0)
    } else {
      None
    };
    // If there's no keys set, then this must be an invalid signature
    if prior.is_none() && latest.is_none() {
      Err(InvalidTransaction::BadProof)?;
    }
    Ok((session, prior, latest))
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      let batch = batch.batch;

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

      // verify the batch size
      // TODO: Merge this encode with the one done by batch_message
      if batch.batch.encode().len() > MAX_BATCH_SIZE {
        Err(InvalidTransaction::ExhaustsResources)?;
      }

      // verify the signature
      let network = batch.batch.network;
      let (current_session, prior, current) = keys_for_network::<T>(network)?;
      let batch_message = batch_message(&batch.batch);
      // Check the prior key first since only a single `Batch` (the last one) will be when prior is
      // Some yet prior wasn't the signing key
      let valid_by_prior =
        if let Some(key) = prior { key.verify(&batch_message, &batch.signature) } else { false };
      let valid = valid_by_prior ||
        (if let Some(key) = current {
          key.verify(&batch_message, &batch.signature)
        } else {
          false
        });
      if !valid {
        Err(InvalidTransaction::BadProof)?;
      }

      // If it wasn't valid by the prior key, meaning it was valid by the current key, the current
      // key is publishing `Batch`s. This should only happen once the current key has verified all
      // `Batch`s published by the prior key, meaning they are accepting the hand-over.
      if prior.is_some() && (!valid_by_prior) {
        ValidatorSets::<T>::retire_set(ValidatorSet {
          network,
          session: Session(current_session.0 - 1),
        });
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

    // Explicitly provide a pre-dispatch which calls validate_unsigned
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ()).map_err(Into::into)
    }
  }
}

pub use pallet::*;
