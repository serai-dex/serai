#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]
#![expect(non_camel_case_types)]
// `parity-scale-codec` generates these
#![cfg_attr(
  feature = "substrate",
  expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::semicolon_if_nothing_returned
  )
)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use borsh::{BorshSerialize, BorshDeserialize};

pub use serai_primitives as primitives;

mod modules;
pub use modules::*;

mod transaction;
pub use transaction::*;

mod block;
pub use block::*;

/// All calls.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Call {
  /// The call for coins.
  Coins(coins::Call) = 0,
  /// The call for validator sets.
  ValidatorSets(validator_sets::Call) = 1,
  /// The call for signals.
  Signals(signals::Call) = 2,
  /// The call for the DEX.
  Dex(dex::Call) = 3,
  /// The call for genesis liquidity.
  GenesisLiquidity(genesis_liquidity::Call) = 4,
  /// The call for `InInstruction`s.
  InInstructions(in_instructions::Call) = 5,
}

impl From<coins::Call> for Call {
  fn from(call: coins::Call) -> Self {
    Self::Coins(call)
  }
}
impl From<validator_sets::Call> for Call {
  fn from(call: validator_sets::Call) -> Self {
    Self::ValidatorSets(call)
  }
}
impl From<signals::Call> for Call {
  fn from(call: signals::Call) -> Self {
    Self::Signals(call)
  }
}
impl From<dex::Call> for Call {
  fn from(call: dex::Call) -> Self {
    Self::Dex(call)
  }
}
impl From<genesis_liquidity::Call> for Call {
  fn from(call: genesis_liquidity::Call) -> Self {
    Self::GenesisLiquidity(call)
  }
}
impl From<in_instructions::Call> for Call {
  fn from(call: in_instructions::Call) -> Self {
    Self::InInstructions(call)
  }
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
  /// The event for coins.
  Coins(coins::Event) = 0,
  /// The event for validator sets.
  ValidatorSets(validator_sets::Event) = 1,
  /// The event for signals.
  Signals(signals::Event) = 2,
  /// The event for the DEX.
  Dex(dex::Event) = 3,
  /// The event for genesis liquidity.
  GenesisLiquidity(genesis_liquidity::Event) = 4,
  /// The event for `InInstruction`s.
  InInstructions(in_instructions::Event) = 5,
  /// The event for `frame-system`.
  System(system::Event) = 6,
}

impl From<coins::Event> for Event {
  fn from(event: coins::Event) -> Self {
    Self::Coins(event)
  }
}
impl From<validator_sets::Event> for Event {
  fn from(event: validator_sets::Event) -> Self {
    Self::ValidatorSets(event)
  }
}
impl From<signals::Event> for Event {
  fn from(event: signals::Event) -> Self {
    Self::Signals(event)
  }
}
impl From<dex::Event> for Event {
  fn from(event: dex::Event) -> Self {
    Self::Dex(event)
  }
}
impl From<genesis_liquidity::Event> for Event {
  fn from(event: genesis_liquidity::Event) -> Self {
    Self::GenesisLiquidity(event)
  }
}
impl From<in_instructions::Event> for Event {
  fn from(event: in_instructions::Event) -> Self {
    Self::InInstructions(event)
  }
}
impl From<system::Event> for Event {
  fn from(event: system::Event) -> Self {
    Self::System(event)
  }
}
