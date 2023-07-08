#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub extern crate alloc;

pub mod sync;
pub mod collections;
pub mod io;

pub use alloc::vec;
pub use alloc::str;
pub use alloc::string;
