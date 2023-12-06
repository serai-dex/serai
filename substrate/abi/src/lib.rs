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

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub enum Call {
  Timestamp(timestamp::Call),
  Coins(coins::Call),
  LiquidityTokens(coins::Call),
  Dex(dex::Call),
  ValidatorSets(validator_sets::Call),
  InInstructions(in_instructions::Call),
  Signals(signals::Call),
  Babe(babe::Call),
  Grandpa(grandpa::Call),
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub enum Event {
  System(system::Event),
  Coins(coins::Event),
  LiquidityTokens(coins::Event),
  Dex(dex::Event),
  ValidatorSets(validator_sets::Event),
  InInstructions(in_instructions::Event),
  Signals(signals::Event),
  Grandpa(grandpa::Event),
}
