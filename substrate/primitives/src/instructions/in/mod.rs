use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::{
  address::{SeraiAddress, ExternalAddress},
  balance::{Amount, ExternalBalance, Balance},
  instructions::OutInstruction,
};

mod batch;
pub use batch::*;

/// The destination for coins.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum Destination {
  /// The Serai address to transfer the coins to.
  Serai(SeraiAddress),
  /// Burn the coins with the included `OutInstruction`.
  Burn(OutInstruction),
}

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
    /// The Serai address to transfer the coins to, after swapping some.
    to: SeraiAddress,
    /// The maximum amount of coins to swap for the intended amount of SRI.
    maximum_swap: Amount,
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
    /// The owner to-be of the added liquidity.
    owner: SeraiAddress,
    /// The amount of SRI to add within the liquidity position.
    sri: Amount,
    /// The minimum amount of the coin to add as liquidity.
    minimum_coin: Amount,
    /// The amount of SRI to swap to and send to the owner to-be to pay for transactions on Serai.
    sri_for_fees: Amount,
  },
  /// Swap the coins.
  Swap {
    /// The minimum balance to receive.
    minimum_out: Balance,
    /// The destination to transfer the balance to.
    ///
    /// If `Destination::Burn`, the balance out will be burnt with the included `OutInstruction`.
    destination: Destination,
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
