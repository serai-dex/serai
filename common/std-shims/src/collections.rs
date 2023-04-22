#[cfg(feature = "std")]
pub use std::collections::*;

#[cfg(not(feature = "std"))]
pub use alloc::collections::*;
#[cfg(not(feature = "std"))]
pub use hashbrown::{HashSet, HashMap};
