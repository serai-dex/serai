#![allow(non_camel_case_types)]

pub mod system;

pub mod timestamp;

pub mod coins;
pub mod dex;

pub mod validator_sets;
pub mod in_instructions;
pub mod signals;

pub mod babe;
pub mod grandpa;

pub use serai_primitives as primitives;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub enum Call {
  System,
  Timestamp(timestamp::Call),
  TransactionPayment,
  Coins(coins::Call),
  LiquidityTokens(coins::Call),
  Dex(dex::Call),
  ValidatorSets(validator_sets::Call),
  InInstructions(in_instructions::Call),
  Signals(signals::Call),
  Babe(babe::Call),
  Grandpa(grandpa::Call),
}

// TODO: Remove this
#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub enum TransactionPaymentEvent {
  TransactionFeePaid { who: serai_primitives::SeraiAddress, actual_fee: u64, tip: u64 },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub enum Event {
  System(system::Event),
  Timestamp,
  TransactionPayment,
  Coins(coins::Event),
  LiquidityTokens(coins::Event),
  Dex(dex::Event),
  ValidatorSets(validator_sets::Event),
  InInstructions(in_instructions::Event),
  Signals(signals::Event),
  Babe,
  Grandpa(grandpa::Event),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Extra {
  pub era: sp_runtime::generic::Era,
  pub nonce: scale::Compact<u32>,
  pub tip: scale::Compact<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedPayloadExtra {
  pub spec_version: u32,
  pub genesis: [u8; 32],
  pub mortality_checkpoint: [u8; 32],
}

pub type Transaction = primitives::Transaction<Call, Extra>;
