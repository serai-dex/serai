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

// amount of blocks in 30 days for 6s per block.
pub const BLOCKS_PER_MONTH: u32 = 10 * 60 * 24 * 30;

/// 180 days of blocks
pub const GENESIS_SRI_TRICKLE_FEED: u64 = 10 * 60 * 24 * 180;

// 100 Million SRI
pub const GENESIS_SRI: u64 = 100_000_000 * 10_u64.pow(8);

// This is the account to hold and manage the genesis liquidity.
pub const GENESIS_LIQUIDITY_ACCOUNT: SeraiAddress = system_address(b"Genesis-liquidity-account");

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Prices {
  pub bitcoin: u64,
  pub monero: u64,
  pub ethereum: u64,
  pub dai: u64,
}

/// The message for the set_initial_price signature.
pub fn set_initial_price_message(set: &ValidatorSet, prices: &Prices) -> Vec<u8> {
  (b"GenesisLiquidity-set_initial_price", set, prices).encode()
}
