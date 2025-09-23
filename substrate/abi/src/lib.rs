#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_camel_case_types)]
#![expect(clippy::cast_possible_truncation)]

extern crate alloc;

pub use serai_primitives as primitives;

pub mod system;

pub mod timestamp;

pub mod coins;
pub mod liquidity_tokens;
pub mod dex;

pub mod validator_sets;

pub mod genesis_liquidity;
pub mod emissions;

pub mod economic_security;

pub mod in_instructions;

pub mod signals;

pub mod babe;
pub mod grandpa;

pub mod tx;

#[derive(
  Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
pub enum Call {
  #[codec(index = 1)]
  Timestamp(timestamp::Call),
  #[codec(index = 3)]
  Coins(coins::Call),
  #[codec(index = 4)]
  LiquidityTokens(liquidity_tokens::Call),
  #[codec(index = 5)]
  Dex(dex::Call),
  #[codec(index = 6)]
  ValidatorSets(validator_sets::Call),
  #[codec(index = 7)]
  GenesisLiquidity(genesis_liquidity::Call),
  #[codec(index = 10)]
  InInstructions(in_instructions::Call),
  #[codec(index = 11)]
  Signals(signals::Call),
  #[codec(index = 12)]
  Babe(babe::Call),
  #[codec(index = 13)]
  Grandpa(grandpa::Call),
}

// TODO: Remove this
#[derive(
  Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
pub enum TransactionPaymentEvent {
  TransactionFeePaid { who: serai_primitives::SeraiAddress, actual_fee: u64, tip: u64 },
}

#[derive(
  Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
pub enum Event {
  #[codec(index = 0)]
  System(system::Event),
  #[codec(index = 2)]
  TransactionPayment(TransactionPaymentEvent),
  #[codec(index = 3)]
  Coins(coins::Event),
  #[codec(index = 4)]
  LiquidityTokens(liquidity_tokens::Event),
  #[codec(index = 5)]
  Dex(dex::Event),
  #[codec(index = 6)]
  ValidatorSets(validator_sets::Event),
  #[codec(index = 7)]
  GenesisLiquidity(genesis_liquidity::Event),
  #[codec(index = 9)]
  EconomicSecurity(economic_security::Event),
  #[codec(index = 10)]
  InInstructions(in_instructions::Event),
  #[codec(index = 11)]
  Signals(signals::Event),
  #[codec(index = 13)]
  Grandpa(grandpa::Event),
}

#[derive(
  Clone, Copy, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub struct Extra {
  pub era: sp_runtime::generic::Era,
  #[codec(compact)]
  pub nonce: u32,
  #[codec(compact)]
  pub tip: u64,
}

#[derive(
  Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub struct SignedPayloadExtra {
  pub spec_version: u32,
  pub tx_version: u32,
  pub genesis: [u8; 32],
  pub mortality_checkpoint: [u8; 32],
}

pub type Transaction = tx::Transaction<Call, Extra>;
