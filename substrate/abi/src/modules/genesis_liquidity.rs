use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  BitVec,
  crypto::RistrettoSignature,
  address::SeraiAddress,
  validator_sets::KeyShares,
  coin::ExternalCoin,
  balance::{Amount, ExternalBalance},
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
    /// The genesis validators who signed off on these values.
    signature_participants: BitVec<{ KeyShares::MAX_PER_SET_U64 }>,
    /// The signature by the genesis validators for these values.
    ///
    /// This is limited to `RistrettoSignature`, instead of using `Signature`, as it does not need
    /// to be versioned. This call will happen once as the network initializes, and never again.
    signature: RistrettoSignature,
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
    /// The minimum amount of SRI to receive.
    sri_minimum: Amount,
    /// The minimum amount of the coin to receive.
    external_coin_minimum: Amount,
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
    to: SeraiAddress,
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
  GenesisLiquidityRemoval {
    /// The account which removed the genesis liquidity.
    by: SeraiAddress,
    /// The amount of genesis liquidity removed.
    genesis_liquidity: ExternalBalance,
    /// The amount of SRI which was burnt by this removal.
    sri_burnt: Amount,
    /// The amount of SRI yielded to the user by this removal.
    sri_yielded: Amount,
    /// The amount of the coin which was yielded to the user by this removal.
    external_coin_yielded: Amount,
  },
}
