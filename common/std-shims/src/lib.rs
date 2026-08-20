#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]
#![cfg_attr(feature = "std", allow(clippy::std_instead_of_core))] // TODO: `core::io`

#[cfg(not(feature = "alloc"))]
pub use core::*;
#[cfg(not(feature = "alloc"))]
pub use core::{alloc, borrow, ffi, fmt, slice, str, task};

#[cfg(not(feature = "std"))]
pub use core::error;

#[cfg(feature = "alloc")]
extern crate alloc as extern_alloc;
#[cfg(feature = "alloc")]
pub use extern_alloc::{alloc, borrow, boxed, ffi, fmt, rc, slice, str, string, task, vec, format};
#[cfg(feature = "std")]
extern crate std;

/// A shim for [`std::collections`](https://doc.rust-lang.org/1.96.0/std/collections).
pub mod collections;
/// A shim for [`std::io`](https://doc.rust-lang.org/1.96.0/std/io).
pub mod io;
/// A shim for [`std::sync`](https://doc.rust-lang.org/1.96.0/std/sync).
pub mod sync;

/// A shim for [`std::prelude`](https://doc.rust-lang.org/1.96.0/std/prelude).
pub mod prelude {
  #[cfg(feature = "alloc")]
  pub use extern_alloc::{
    format, vec,
    borrow::ToOwned,
    boxed::Box,
    vec::Vec,
    string::{String, ToString},
  };
}
