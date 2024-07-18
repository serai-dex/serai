#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use sp_std::vec::Vec;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use serai_primitives::*;
use validator_sets_primitives::ValidatorSet;

pub const INITIAL_GENESIS_LP_SHARES: u64 = 10_000;

// This is the account to hold and manage the genesis liquidity.
pub const GENESIS_LIQUIDITY_ACCOUNT: SeraiAddress = system_address(b"GenesisLiquidity-account");

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Values {
  pub monero: u64,
  pub ether: u64,
  pub dai: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LiquidityAmount {
  pub shares: u64,
  pub coins: u64,
}

impl LiquidityAmount {
  pub fn zero() -> Self {
    LiquidityAmount { shares: 0, coins: 0 }
  }
}

/// The message for the oraclize_values signature.
pub fn oraclize_values_message(set: &ValidatorSet, values: &Values) -> Vec<u8> {
  (b"GenesisLiquidity-oraclize_values", set, values).encode()
}
