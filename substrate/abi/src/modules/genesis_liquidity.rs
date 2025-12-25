use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  crypto::Signature, address::SeraiAddress, coin::ExternalCoin, balance::ExternalBalance,
  genesis_liquidity::GenesisValues,
};

/// The address used for to hold genesis liquidity for a pool.
pub fn address(coin: ExternalCoin) -> SeraiAddress {
  SeraiAddress::system(borsh::to_vec(&(b"GenesisLiquidity", coin)).unwrap())
}

/// A call to the genesis liquidity module.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Oraclize the values of the coins available on genesis, relative to BTC.
  ///
  /// This will trigger the addition of the liquidity into the pools and their initialization.
  oraclize_values {
    /// The values of the non-Bitcoin external coins.
    values: GenesisValues,
    /// The signature by the genesis validators for these values.
    signature: Signature,
  },
  /// Transfer genesis liquidity.
  transfer_genesis_liquidity {
    /// The account to transfer the liquidity to.
    to: SeraiAddress,
    /// The genesis liquidity to transfer.
    genesis_liquidity: ExternalBalance,
  },
  /// Remove genesis liquidity.
  remove_genesis_liquidity {
    /// The genesis liquidity to remove.
    genesis_liquidity: ExternalBalance,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::oraclize_values { .. } => false,
      Call::transfer_genesis_liquidity { .. } | Call::remove_genesis_liquidity { .. } => true,
    }
  }
}

/// An event from the genesis liquidity module.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// Genesis liquidity added.
  GenesisLiquidityAdded {
    /// The recipient of the genesis liquidity.
    recipient: SeraiAddress,
    /// The coins added as genesis liquidity.
    genesis_liquidity: ExternalBalance,
  },
  /// Genesis liquidity added.
  GenesisLiquidityTransferred {
    /// The address transferred from.
    from: SeraiAddress,
    /// The address transferred to.
    to: SeraiAddress,
    /// The genesis liquidity transferred.
    genesis_liquidity: ExternalBalance,
  },
  /// Genesis liquidity removed.
  GenesisLiquidityRemoved {
    /// The account which removed the genesis liquidity.
    from: SeraiAddress,
    /// The amount of genesis liquidity removed.
    genesis_liquidity: ExternalBalance,
  },
}
