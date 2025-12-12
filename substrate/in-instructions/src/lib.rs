#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
mod pallet {
  use sp_core::sr25519::Public;
  use sp_application_crypto::RuntimePublic;

  use frame_support::{pallet_prelude::*, dispatch::RawOrigin};
  use frame_system::pallet_prelude::*;

  use serai_abi::{primitives::prelude::*, in_instructions::Event};

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;

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

    /// Execute an `InInstructionWithBalance`.
    ///
    /// We execute this within a database layer to ensure it's atomic, executing entirely or not at
    /// all.
    #[frame_support::transactional]
    fn execute(instruction: InInstructionWithBalance) -> DispatchResult {
      let InInstructionWithBalance { instruction, balance: external_balance } = instruction;
      let balance = <Balance as From<ExternalBalance>>::from(external_balance);

      // Mint the balance to ourself
      let address = serai_abi::in_instructions::address();
      Coins::<T>::mint(address.into(), balance)?;

      match instruction {
        InInstruction::GenesisLiquidity(address) => {
          serai_genesis_liquidity_pallet::Pallet::<T>::add_liquidity(address, external_balance)?;
        }
        InInstruction::SwapToStakedSri { validator, minimum } => {
          todo!("TODO {validator:?} {minimum:?}")
        }
        InInstruction::TransferWithSwap { to, maximum_to_swap, sri } => {
          serai_dex_pallet::Pallet::<T>::swap_for(
            RawOrigin::Signed(address.into()).into(),
            Balance { coin: Coin::Serai, amount: sri },
            Balance { coin: balance.coin, amount: maximum_to_swap },
          )?;

          Coins::<T>::transfer_fn(
            address.into(),
            to.into(),
            Balance {
              coin: balance.coin,
              amount: Coins::<T>::balance(Public::from(address), balance.coin),
            },
          )?;
          Coins::<T>::transfer_fn(
            address.into(),
            to.into(),
            Balance {
              coin: Coin::Serai,
              amount: Coins::<T>::balance(Public::from(address), Coin::Serai),
            },
          )?;
        }
        InInstruction::Transfer { to } => {
          Coins::<T>::transfer_fn(address.into(), to.into(), balance)?;
        }
        InInstruction::SwapAndAddLiquidity {
          address: destination,
          coin,
          sri_minimum,
          sri_for_fees,
        } => {
          let external_coin = external_balance.coin;
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(address.into()).into(),
            Balance {
              coin: Coin::External(external_coin),
              amount: (balance.amount - coin).ok_or(serai_dex_pallet::Error::<T>::Underflow)?,
            },
            Balance {
              coin: Coin::Serai,
              amount: (sri_minimum + sri_for_fees).ok_or(serai_dex_pallet::Error::<T>::Overflow)?,
            },
          )?;

          let sri_intended = (Coins::<T>::balance(Public::from(address), Coin::Serai) -
            sri_for_fees)
            .expect("swapped to amount sufficient for minimum, fees, but received less than fees?");
          let coin_intended = coin;
          let coin_minimum = coin;
          serai_dex_pallet::Pallet::<T>::add_liquidity(
            RawOrigin::Signed(address.into()).into(),
            external_coin,
            sri_intended,
            coin_intended,
            sri_minimum,
            coin_minimum,
          )?;

          // Transfer the rest, which will be more than the amount requested for fees, to the
          // destination
          Coins::<T>::transfer_fn(
            address.into(),
            destination.into(),
            Balance {
              coin: Coin::Serai,
              amount: Coins::<T>::balance(Public::from(address), Coin::Serai),
            },
          )?;
        }
        InInstruction::Swap { address: destination, minimum_to_receive } => {
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(address.into()).into(),
            balance,
            minimum_to_receive,
          )?;

          let coin = minimum_to_receive.coin;
          let received_amount = Coins::<T>::balance(Public::from(address), coin);
          let received = Balance { coin, amount: received_amount };
          Coins::<T>::transfer_fn(address.into(), destination.into(), received)?;
        }
        InInstruction::SwapOut { instruction, minimum_to_receive } => {
          serai_dex_pallet::Pallet::<T>::swap(
            RawOrigin::Signed(address.into()).into(),
            balance,
            minimum_to_receive.into(),
          )?;

          let coin = minimum_to_receive.coin;
          let received_amount = Coins::<T>::balance(Public::from(address), Coin::from(coin));
          let received = ExternalBalance { coin, amount: received_amount };
          Coins::<T>::burn_with_instruction(
            RawOrigin::Signed(address.into()).into(),
            OutInstructionWithBalance { instruction, balance: received },
          )?;
        }
      }

      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Execute a batch of `InInstruction`s.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      let batch = batch.batch;
      let network = batch.network();

      let mut in_instruction_results = bitvec::vec::BitVec::new();
      for instruction in batch.instructions() {
        in_instruction_results.push(Self::execute(instruction.clone()).is_ok());
      }

      // The publishing session is always the current session
      let publishing_session =
        serai_validator_sets_pallet::Pallet::<T>::current_session(NetworkId::from(network))
          .expect("`SignedBatch` for a network without a session was validated");

      Self::emit_event(Event::Batch {
        network,
        publishing_session,
        id: batch.id(),
        external_network_block_hash: batch.external_network_block_hash(),
        in_instructions_hash: sp_core::blake2_256(&borsh::to_vec(batch.instructions()).unwrap()),
        in_instruction_results,
      });

      Ok(())
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

      // Verify every coin with the `Batch` corresponds to this network
      for instruction in batch.batch.instructions() {
        if instruction.balance.coin.network() != network {
          Err(InvalidTransaction::Custom(2))?;
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
