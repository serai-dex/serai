#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use extern_alloc::collections::*;
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use hashbrown::{HashSet, HashMap};

#[cfg(feature = "std")]
pub use std::collections::*;
