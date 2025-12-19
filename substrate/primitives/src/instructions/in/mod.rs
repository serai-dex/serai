use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::{
  address::{SeraiAddress, ExternalAddress},
  balance::{Amount, ExternalBalance, Balance},
  instructions::OutInstruction,
};

mod batch;
pub use batch::*;

/// An instruction on how to handle coins in.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum InInstruction {
  /// Add the coins as genesis liquidity.
  GenesisLiquidity(SeraiAddress),
  /// Use the coins to swap to staked SRI, pre-economic security.
  SwapToStakedSri {
    /// The validator to allocate the stake to.
    validator: SeraiAddress,
    /// The minimum amount of staked SRI to swap to.
    minimum: Amount,
  },
  /// Transfer the coins to a Serai address, swapping some for SRI.
  TransferWithSwap {
    /// The Serai address to transfer the coins to.
    to: SeraiAddress,
    /// The maximum amount of coins to swap for the intended amount of SRI.
    maximum_to_swap: Amount,
    /// The SRI amount to swap some of the coins for.
    sri: Amount,
  },
  /// Transfer the coins to a Serai address.
  Transfer {
    /// The Serai address to transfer the coins to.
    to: SeraiAddress,
  },
  /// Swap part of the coins to SRI and add the coins as liquidity.
  SwapAndAddLiquidity {
    /// The recipient to-be of the added liquidity.
    address: SeraiAddress,
    /// The amount of the coin to add within the liquidity position.
    coin: Amount,
    /// The minimum amount of SRI to add as liquidity.
    sri_minimum: Amount,
    /// The amount of SRI to swap to and send to the owner to-be to pay for transactions on Serai.
    sri_for_fees: Amount,
  },
  /// Swap the coins.
  Swap {
    /// The destination to received the coins swapped to with.
    address: SeraiAddress,
    /// The minimum balance to receive from the swap.
    minimum_to_receive: Balance,
  },
  /// Swap the coins, burning them with the included `OutInstruction`.
  SwapOut {
    /// The instruction to burn the coins swapped to with.
    instruction: OutInstruction,
    /// The minimum balance to receive from the swap.
    minimum_to_receive: ExternalBalance,
  },
}

/// An instruction on how to handle coins in with the address to return the coins to on error.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct RefundableInInstruction {
  /// The instruction on how to handle coins in.
  pub instruction: InInstruction,
  /// The address to return the coins to on error.
  pub return_address: Option<ExternalAddress>,
}

/// An instruction on how to handle coins in with the balance to use for the coins in.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct InInstructionWithBalance {
  /// The instruction on how to handle coins in.
  pub instruction: InInstruction,
  /// The coins in.
  pub balance: ExternalBalance,
}
