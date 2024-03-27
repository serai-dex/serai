#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use serai_primitives::*;

// amount of blocks in 30 days for 6s per block.
pub const BLOCKS_PER_MONTH: u32 = 10 * 60 * 24 * 30;

/// 180 days of blocks
pub const GENESIS_SRI_TRICKLE_FEED: u64 = 10 * 60 * 24 * 180;

// 100 Million SRI
pub const GENESIS_SRI: u64 = 100_000_000 * 10_u64.pow(8);

// This is the account which will be the origin for any dispatched `InInstruction`s.
pub const GENESIS_LIQUIDITY_ACCOUNT: SeraiAddress = system_address(b"Genesis-liquidity-account");
