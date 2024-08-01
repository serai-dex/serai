use crate::BlockNumber;

// 1 MB
pub const BLOCK_SIZE: u32 = 1024 * 1024;
// 6 seconds
pub const TARGET_BLOCK_TIME: u64 = 6;

/// Measured in blocks.
pub const MINUTES: BlockNumber = 60 / TARGET_BLOCK_TIME;
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;
pub const WEEKS: BlockNumber = DAYS * 7;
pub const MONTHS: BlockNumber = WEEKS * 4;

/// 6 months of blocks
pub const GENESIS_SRI_TRICKLE_FEED: u64 = MONTHS * 6;

// 100 Million SRI
pub const GENESIS_SRI: u64 = 100_000_000 * 10_u64.pow(8);

/// This needs to be long enough for arbitrage to occur and make holding any fake price up
/// sufficiently unrealistic.
#[allow(clippy::cast_possible_truncation)]
pub const ARBITRAGE_TIME: u16 = (2 * HOURS) as u16;

/// Since we use the median price, double the window length.
///
/// We additionally +1 so there is a true median.
pub const MEDIAN_PRICE_WINDOW_LENGTH: u16 = (2 * ARBITRAGE_TIME) + 1;

/// Amount of blocks per epoch in the fast-epoch feature that is used in tests.
pub const FAST_EPOCH_DURATION: u64 = 2 * MINUTES;

/// Amount of blocks for the initial period era for the emissions for fast epoc feature.
pub const FAST_EPOCH_INITIAL_PERIOD: u64 = FAST_EPOCH_DURATION * 2;
