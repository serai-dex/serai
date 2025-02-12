#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_camel_case_types)]

extern crate alloc;

use borsh::{BorshSerialize, BorshDeserialize};

pub use serai_primitives as primitives;

/// Call/Event for the system.
pub mod system;

/// Call/Event for coins.
pub mod coins;

/// Call/Event for validator sets.
pub mod validator_sets;
/// Call/Event for signals.
pub mod signals;

/// Call/Event for the DEX.
pub mod dex;

/// Call/Event for genesis liquidity.
pub mod genesis_liquidity;
/// Event for economic security.
pub mod economic_security;

/// Call/Event for `InInstruction`s.
pub mod in_instructions;

mod transaction;
pub use transaction::*;

mod block;
pub use block::*;

/// All calls.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Call {
  // The call for the system.
  // System(system::Call) = 0,
  /// The call for coins.
  Coins(coins::Call) = 1,
  /// The call for validator sets.
  ValidatorSets(validator_sets::Call) = 2,
  /// The call for signals.
  Signals(signals::Call) = 3,
  /// The call for the DEX.
  Dex(dex::Call) = 4,
  /// The call for genesis liquidity.
  GenesisLiquidity(genesis_liquidity::Call) = 5,
  // The call for economic security.
  // EconomicSecurity = 6,
  /// The call for `InInstruction`s.
  InInstructions(in_instructions::Call) = 7,
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::Coins(call) => call.is_signed(),
      Call::ValidatorSets(call) => call.is_signed(),
      Call::Signals(call) => call.is_signed(),
      Call::Dex(call) => call.is_signed(),
      Call::GenesisLiquidity(call) => call.is_signed(),
      Call::InInstructions(call) => call.is_signed(),
    }
  }
}

/// All events.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Event {
  /// The event for the system.
  System(system::Event) = 0,
  /// The event for coins.
  Coins(coins::Event) = 1,
  /// The event for validator sets.
  ValidatorSets(validator_sets::Event) = 2,
  /// The event for signals.
  Signals(signals::Event) = 3,
  /// The event for the DEX.
  Dex(dex::Event) = 4,
  /// The event for genesis liquidity.
  GenesisLiquidity(genesis_liquidity::Event) = 5,
  /// The event for economic security.
  EconomicSecurity(economic_security::Event) = 6,
  /// The event for `InInstruction`s.
  InInstructions(in_instructions::Event) = 7,
}
