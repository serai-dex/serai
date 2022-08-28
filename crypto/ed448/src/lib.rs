#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "hazmat")]
mod hazmat;
#[cfg(feature = "hazmat")]
pub use hazmat::*;
