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
  use sp_std::vec;

  use frame_support::pallet_prelude::*;
  use frame_system::{pallet_prelude::*, RawOrigin};

  use tokens_pallet::{Config as TokensConfig, Pallet as Tokens, primitives::OutInstruction};
  use validator_sets_pallet::{
    primitives::{Session, ValidatorSet},
    Config as ValidatorSetsConfig, Pallet as ValidatorSets,
  };

  use serai_primitives::{Coin, SubstrateAmount, Amount, Balance, PublicKey};

  use pallet_asset_conversion::{Config as DexConfig, Pallet as Dex};
  use pallet_balances::{Config as BalancesConfig, Pallet as BalancesPallet};

  use super::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + ValidatorSetsConfig
    + TokensConfig
    + DexConfig<MultiAssetId = Coin, AssetBalance = SubstrateAmount>
    + BalancesConfig<Balance = SubstrateAmount>
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch { network: NetworkId, id: u32, block: BlockHash, instructions_hash: [u8; 32] },
    InstructionFailure { network: NetworkId, id: u32, index: u32 },
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Coin and OutAddress types don't match.
    InvalidAddressForCoin,
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
    fn execute(instruction: InInstructionWithBalance) -> DispatchResult {
      match instruction.instruction {
        InInstruction::Transfer(address) => Tokens::<T>::mint(address, instruction.balance),
        InInstruction::Dex(call) => {
          // This will only be initiated by external chain txs. That is why we only need
          // adding liquidity and swaps. Other functionalities(create_pool, remove_liq etc.)
          // might be called directly from serai as a native operation.
          //
          // Hence, AddLiquidity call here actually swaps and adds liquidity.
          // we will swap half of the given coin for SRI to be able to
          // provide symmetric liquidity. So the pool has be be created before
          // for this to be successful.
          //
          // And for swaps, they are done on an internal address like a temp account.
          // we mint the deposited coin into that account, do swap on it and burn the
          // received coin. This way account will be back on initial balance(since the minted coin
          // will be moved to pool account.) and burned coin will be seen by processor and sent
          // to given external address.

          match call {
            DexCall::AddLiquidity(address) => {
              let origin = RawOrigin::Signed(IN_INSTRUCTION_EXECUTOR.into());
              let coin = instruction.balance.coin;

              // mint the given coin on the account
              Tokens::<T>::mint(IN_INSTRUCTION_EXECUTOR, instruction.balance);

              // swap half of it for SRI
              let half = instruction.balance.amount.0 / 2;
              let path = BoundedVec::truncate_from(vec![coin, Coin::Serai]);
              Dex::<T>::swap_exact_tokens_for_tokens(
                origin.clone().into(),
                path,
                half,
                1, // minimum out, so we accept whatever we get.
                IN_INSTRUCTION_EXECUTOR.into(),
                false,
              )?;

              // get how much we got for our swap
              // TODO: Do we want to use the `usable_balance`?
              let sri_amount =
                BalancesPallet::<T>::free_balance(PublicKey::from(IN_INSTRUCTION_EXECUTOR));

              // add liquidity
              Dex::<T>::add_liquidity(
                origin.clone().into(),
                coin,
                Coin::Serai,
                half,
                sri_amount,
                1,
                1,
                address.into(),
              )?;

              // TODO: minimums are set to 1 above to guarantee successful adding liq call.
              // Ideally we either get this info from user or send the leftovers back to user.
              // Let's send the leftovers back to user for now.
              let coin_balance = Tokens::<T>::balance(coin, IN_INSTRUCTION_EXECUTOR);
              let sri_balance =
                BalancesPallet::<T>::free_balance(PublicKey::from(IN_INSTRUCTION_EXECUTOR));

              if coin_balance != 0 {
                Tokens::<T>::transfer(origin.clone().into(), coin, address, coin_balance)?;
              }
              if sri_balance != 0 {
                // unwrap here. First, it doesn't panic for full amount,
                // second we should empty IIE account anyway.
                BalancesPallet::<T>::transfer_allow_death(origin.into(), address, sri_balance)
                  .unwrap();
              }
            }
            DexCall::Swap(out_balance, out_address) => {
              let send_to_external = !out_address.is_native();
              let native_coin = out_balance.coin.is_native();

              // we can't send native coin to external chain
              if native_coin && send_to_external {
                Err(Error::<T>::InvalidAddressForCoin)?;
              }

              // mint the given coin on our account
              Tokens::<T>::mint(IN_INSTRUCTION_EXECUTOR, instruction.balance);

              // get the path
              let mut path = vec![instruction.balance.coin, Coin::Serai];
              if !native_coin {
                path.push(out_balance.coin);
              }

              // get the swap address
              // if the address is internal, we can directly swap to it.
              // if not, we swap to ourselves and burn the coins to send them back
              // on the external chain.
              let send_to = if send_to_external {
                IN_INSTRUCTION_EXECUTOR
              } else {
                out_address.clone().as_native().unwrap()
              };

              // do the swap
              let origin = RawOrigin::Signed(IN_INSTRUCTION_EXECUTOR.into());
              Dex::<T>::swap_exact_tokens_for_tokens(
                origin.into(),
                BoundedVec::truncate_from(path),
                instruction.balance.amount.0,
                out_balance.amount.0,
                send_to.into(),
                false,
              )?;

              // burn the received coins so that they sent back to the user
              // if it is requested to an external address.
              if send_to_external {
                // see how much we got
                let coin2_balance = Tokens::<T>::balance(out_balance.coin, IN_INSTRUCTION_EXECUTOR);
                let balance = Balance { coin: out_balance.coin, amount: Amount(coin2_balance) };
                // TODO: data shouldn't come here from processor just to go back to it.
                Tokens::<T>::burn_internal(
                  IN_INSTRUCTION_EXECUTOR,
                  balance,
                  OutInstruction { address: out_address.as_external().unwrap(), data: None },
                )?;
              }
            }
          }
        }
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
