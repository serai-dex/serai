use serai_primitives::{Balance, SeraiAddress};

pub use serai_coins_primitives as primitives;
use primitives::OutInstructionWithBalance;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Call {
  transfer { to: SeraiAddress, balance: Balance },
  burn { balance: Balance },
  burn_with_instruction { instruction: OutInstructionWithBalance },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum LiquidityTokensCall {
  transfer { to: SeraiAddress, balance: Balance },
  burn { balance: Balance },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  Mint { to: SeraiAddress, balance: Balance },
  Burn { from: SeraiAddress, balance: Balance },
  BurnWithInstruction { from: SeraiAddress, instruction: OutInstructionWithBalance },
  Transfer { from: SeraiAddress, to: SeraiAddress, balance: Balance },
}
