use core::time::Duration;

/// The target block time.
pub const TARGET_BLOCK_TIME: Duration = Duration::from_secs(6);

/// The intended duration for a session.
// 1 week
pub const SESSION_LENGTH: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The maximum amount of key shares per set.
pub const MAX_KEY_SHARES_PER_SET: u16 = 150;
/// The maximum amount of key shares per set, as an u32.
pub const MAX_KEY_SHARES_PER_SET_U32: u32 = MAX_KEY_SHARES_PER_SET as u32;
