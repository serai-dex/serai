#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod sync;
pub mod collections;
pub mod io;

pub mod vec {
  pub use alloc::vec::*;
}

pub mod str {
  pub use alloc::str::*;
}

pub mod string {
  pub use alloc::string::*;
}
