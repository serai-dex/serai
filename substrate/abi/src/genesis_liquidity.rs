use serai_primitives::*;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Call {
  // This call is just a place holder so that abi works as expected.
  empty_call,
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  GenesisLiquidityAdded { by: SeraiAddress, balance: Balance },
  GenesisLiquidityRemoved { by: SeraiAddress, balance: Balance },
  GenesisLiquidityAddedToPool { coin1: Balance, coin2: Balance },
  EconomicSecurityReached { network: NetworkId },
}
