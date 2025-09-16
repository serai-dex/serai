use core::time::Duration;

/// The target block time.
pub const TARGET_BLOCK_TIME: Duration = Duration::from_secs(6);

/// The intended duration for a session.
// 1 week
pub const SESSION_LENGTH: Duration = Duration::from_secs(7 * 24 * 60 * 60);
