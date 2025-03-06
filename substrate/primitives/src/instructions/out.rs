use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::{address::ExternalAddress, balance::ExternalBalance};

/// An instruction on how to transfer coins out.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
pub enum OutInstruction {
  /// Transfer to the specified address.
  Transfer(ExternalAddress),
}

/// An instruction on how to transfer coins out with the balance to use for the transfer out.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
pub struct OutInstructionWithBalance {
  /// The instruction on how to transfer coins out.
  pub instruction: OutInstruction,
  /// The balance to use for the transfer out.
  pub balance: ExternalBalance,
}
