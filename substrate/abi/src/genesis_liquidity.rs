pub use serai_genesis_liquidity_primitives as primitives;

use serai_primitives::*;
use primitives::*;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Call {
  remove_coin_liquidity { balance: ExternalBalance },
  oraclize_values { values: Values, signature: Signature },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  GenesisLiquidityAdded { by: SeraiAddress, balance: ExternalBalance },
  GenesisLiquidityRemoved { by: SeraiAddress, balance: ExternalBalance },
  GenesisLiquidityAddedToPool { coin: ExternalBalance, sri: Amount },
}
