use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  crypto::Signature, address::SeraiAddress, balance::ExternalBalance, genesis::GenesisValues,
};

/// A call to the genesis liquidity.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Oraclize the value of non-Bitcoin external coins relative to Bitcoin.
  oraclize_values {
    /// The values of the non-Bitcoin external coins.
    values: GenesisValues,
    /// The signature by the genesis validators for these values.
    signature: Signature,
  },
  /// Remove liquidity.
  remove_liquidity {
    /// The genesis liquidity to remove.
    balance: ExternalBalance,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::oraclize_values { .. } => false,
      Call::remove_liquidity { .. } => true,
    }
  }
}

/// An event from the genesis liquidity.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// Genesis liquidity added.
  GenesisLiquidityAdded {
    /// The recipient of the genesis liquidity.
    recipient: SeraiAddress,
    /// The coins added as genesis liquidity.
    balance: ExternalBalance,
  },
  /// Genesis liquidity removed.
  GenesisLiquidityRemoved {
    /// The account which removed the genesis liquidity.
    origin: SeraiAddress,
    /// The amount of genesis liquidity removed.
    balance: ExternalBalance,
  },
}
