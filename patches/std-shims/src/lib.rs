#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

pub extern crate alloc;
pub use std_shims::{str, vec, string, collections, io, sync, prelude};
