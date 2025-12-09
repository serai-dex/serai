#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

#[expect(clippy::cast_possible_truncation)]
#[frame_support::pallet]
mod pallet {
  use sp_application_crypto::RuntimePublic;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_abi::{primitives::prelude::*, in_instructions::Event};

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;
  type LiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::LiquidityTokensInstance>;

  use super::*;

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_validator_sets_pallet::Config
    + serai_signals_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
    + serai_dex_pallet::Config
    + serai_genesis_liquidity_pallet::Config
  {
  }

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T> {}

  /// The block the last batch was published during.
  ///
  /// This is used to restrict publication of batches to once-per-block, limiting the impact of a
  /// compromised publisher from bloating the Serai blockchain with spam.
  #[pallet::storage]
  type BlockOfLastBatch<T: Config> =
    StorageMap<_, Identity, ExternalNetworkId, BlockNumberFor<T>, OptionQuery>;

  /// The ID of the last batch which was published.
  #[pallet::storage]
  type LastBatch<T: Config> = StorageMap<_, Identity, ExternalNetworkId, u32, OptionQuery>;

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    fn emit_event(event: Event) {
      Core::<T>::emit_event(event)
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Execute a batch of `InInstruction`s.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      todo!("TODO")
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      let batch = match call {
        Call::execute_batch { batch } => batch,
        Call::__Ignore(_, _) => Err(InvalidTransaction::Call)?,
      };

      let network = batch.batch.network();

      // Verify the network isn't halted
      if serai_signals_pallet::Pallet::<T>::halted(network) {
        Err(InvalidTransaction::Custom(1))?;
      }

      // Verify the `Batch`'s signature
      let mut signed_by_latest_decided_session = false;
      {
        let message = batch.batch.publish_batch_message();
        let signed_by_session = |session| {
          let Some(key) =
            serai_validator_sets_pallet::Pallet::<T>::oraclization_key(ExternalValidatorSet {
              network,
              session,
            })
          else {
            return false;
          };
          key.verify(&message, &batch.signature.into())
        };
        let Some(current_session) =
          serai_validator_sets_pallet::Pallet::<T>::current_session(NetworkId::from(network))
        else {
          Err(InvalidTransaction::BadProof)?
        };
        if !signed_by_session(current_session) {
          let latest_decided_session =
            serai_validator_sets_pallet::Pallet::<T>::latest_decided_session(NetworkId::from(
              network,
            ))
            .expect("current session yet never one decided?");
          if !signed_by_session(latest_decided_session) {
            Err(InvalidTransaction::BadProof)?;
          }
          signed_by_latest_decided_session = true;
        }
      }

      // Verify this is the first `Batch` for this block
      let current_block_number = frame_system::Pallet::<T>::block_number();
      if BlockOfLastBatch::<T>::get(network) == Some(current_block_number) {
        // This transaction is valid in the future, the next block, but not now
        Err(InvalidTransaction::Future)?;
      }

      // Verify this `Batch` descends immediately from the prior `Batch`
      let required_last_batch = batch.batch.id().checked_sub(1);
      {
        let last_batch = LastBatch::<T>::get(network);
        if last_batch < required_last_batch {
          Err(InvalidTransaction::Future)?;
        }
        if last_batch > required_last_batch {
          Err(InvalidTransaction::Stale)?;
        }
      }

      /*
        Set the metadata fields as necessary for further batches to be verified. While this is
        mutating the state within the verification function, it's necessary for the verification of
        the following transactions.

        Additionally, we know these state changes occur as tests verify we can publish `Batch`es
        and have the `LastBatch` field be incremented.
      */
      BlockOfLastBatch::<T>::set(network, Some(current_block_number));
      LastBatch::<T>::set(network, Some(batch.batch.id()));
      if signed_by_latest_decided_session {
        // Because the latest decided session, which is not the current session, has taken over
        // for publishing `Batch`es, it has agreed to become the current session
        serai_validator_sets_pallet::Pallet::<T>::accept_handover(network);
      }

      let mut builder = ValidTransaction::with_tag_prefix("InInstructions");
      if let Some(required_last_batch) = required_last_batch {
        // TODO: Should this replace the DB mutations present within this verification function?
        builder = builder.and_requires((network, required_last_batch));
      }
      builder
        .and_provides((network, batch.batch.id()))
        // Set a 10 block longevity, though this should be included in the next block
        .longevity(10)
        .propagate(true)
        .build()
    }

    /// Explicitly provide a `pre_dispatch` which calls `validate_unsigned`.
    ///
    /// This is reasonably assumed, and the current provided implementation, but not guaranteed by
    /// the documentation.
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ())
    }
  }
}

pub use pallet::*;
