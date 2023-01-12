#![cfg_attr(not(feature = "std"), no_std)]

mod amount;
pub use amount::*;

mod coins;
pub use coins::*;

pub type NativeAddress = sp_core::sr25519::Public;
