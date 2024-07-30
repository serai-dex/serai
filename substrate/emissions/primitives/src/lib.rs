#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use serai_primitives::{SeraiAddress, system_address};

// Protocol owned liquidity account.
pub const POL_ACCOUNT: SeraiAddress = system_address(b"PoL-account");

/// Amount of blocks in 30 days for 6s per block.
const BLOCKS_PER_MONTH: u64 = 10 * 60 * 24 * 30;

/// INITIAL_REWARD = 100,000 SRI / BLOCKS_PER_DAY for 60 days
pub const INITIAL_REWARD_PER_BLOCK: u64 = 100_000 * 10u64.pow(8) / (BLOCKS_PER_MONTH / 30);

/// REWARD = 20M SRI / BLOCKS_PER_YEAR
pub const REWARD_PER_BLOCK: u64 = 20_000_000 * 10u64.pow(8) / (BLOCKS_PER_MONTH * 12);

/// 20% of all stake desired to be for Serai network(2/10)
pub const SERAI_VALIDATORS_DESIRED_PERCENTAGE: u64 = 2;

/// Desired unused capacity ratio for a network assuming capacity is 10,000.
pub const DESIRED_DISTRIBUTION: u64 = 1_000;

/// Percentage scale for the validator vs. pool reward distribution.
pub const ACCURACY_MULTIPLIER: u64 = 10_000;

/// The block to target for economic security
pub const SECURE_BY: u64 = BLOCKS_PER_MONTH * 12;
