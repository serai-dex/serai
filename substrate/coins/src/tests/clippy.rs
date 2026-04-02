//! These tests ensure `clippy` does successfully raise a warning when the `pallet::Call` functions
//! are used directly, as the caller is liable to ensure these methods are only used when the
//! instance is `CoinsInstance`. For other instances, the public functions which _aren't_ part of
//! the `Call` MUST be used.
//!
//! We ensure `clippy` raises a warning by using the `expect` annotation. When `clippy` is ran on
//! this file, it will pass without issue, or it will warn that the `expect` was unnecessary
//! (meaning the intended warning is not being emitted as expected).

use super::*;

use serai_abi::primitives::{address::ExternalAddress, instructions::OutInstruction};

#[test]
fn transfer_call_raises_warning() {
  if false {
    #[expect(clippy::disallowed_methods)]
    let _ = Coins::transfer(
      Some(SeraiAddress([0; 32])).into(),
      SeraiAddress([0; 32]),
      Balance { coin: Coin::Serai, amount: Amount(0) },
    );
  }
}

#[test]
fn burn_fn_raises_warning() {
  if false {
    #[expect(clippy::disallowed_methods)]
    let _ = Coins::burn_fn(SeraiAddress([0; 32]), Balance { coin: Coin::Serai, amount: Amount(0) });
  }
}

#[test]
fn burn_call_raises_warning() {
  if false {
    #[expect(clippy::disallowed_methods)]
    let _ = Coins::burn(
      Some(SeraiAddress([0; 32])).into(),
      Balance { coin: Coin::Serai, amount: Amount(0) },
    );
  }
}

#[test]
fn burn_with_instruction_call_raises_warning() {
  if false {
    #[expect(clippy::disallowed_methods)]
    let _ = Coins::burn_with_instruction(
      Some(SeraiAddress([0; 32])).into(),
      OutInstructionWithBalance {
        instruction: OutInstruction::Transfer(ExternalAddress::try_from(vec![]).unwrap()),
        balance: ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(0) },
      },
    );
  }
}
