use alloc::vec::Vec;

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::balance::Amount;

/// The value of non-Bitcoin externals coins present at genesis, relative to Bitcoin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct GenesisValues {
  /// The value of Ether, relative to Bitcoin.
  pub ether: Amount,
  /// The value of DAI, relative to Bitcoin.
  pub dai: Amount,
  /// The value of Monero, relative to Bitcoin.
  pub monero: Amount,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(GenesisValues);

impl GenesisValues {
  /// The message for the oraclize_values signature.
  pub fn oraclize_values_message(&self) -> Vec<u8> {
    borsh::to_vec(&(b"GenesisLiquidity-oraclize_values", self)).unwrap()
  }
}
