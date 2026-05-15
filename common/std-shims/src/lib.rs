#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#![allow(clippy::alloc_instead_of_core, clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

#[cfg(not(feature = "alloc"))]
pub use core::*;
#[cfg(not(feature = "alloc"))]
pub use core::{alloc, borrow, ffi, fmt, slice, str, task};

#[cfg(not(feature = "std"))]
#[rustversion::before(1.81)]
pub mod error {
  use core::fmt::Debug::Display;
  pub trait Error: Debug + Display {}
}
#[cfg(not(feature = "std"))]
#[rustversion::since(1.81)]
pub use core::error;

#[cfg(feature = "alloc")]
extern crate alloc as extern_alloc;
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use extern_alloc::{alloc, borrow, boxed, ffi, fmt, rc, slice, str, string, task, vec, format};
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
pub use std::{alloc, borrow, boxed, error, ffi, fmt, rc, slice, str, string, task, vec, format};

pub mod collections;
pub mod io;
pub mod sync;

pub mod prelude {
  // Shim the `std` prelude
  #[cfg(feature = "alloc")]
  pub use extern_alloc::{
    format, vec,
    borrow::ToOwned,
    boxed::Box,
    vec::Vec,
    string::{String, ToString},
  };

  // Shim `div_ceil`
  #[rustversion::before(1.73)]
  #[doc(hidden)]
  pub trait StdShimsDivCeil {
    /// Perform a division which rounds non-integer results up.
    ///
    /// This function MAY panic when `denominator == 0` or the result is not representable within
    /// `Self`.
    fn div_ceil(self, denominator: Self) -> Self;
  }
  #[rustversion::before(1.73)]
  mod impl_divceil {
    use super::StdShimsDivCeil;
    impl StdShimsDivCeil for u8 {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + u8::from(has_remainder)
      }
    }
    impl StdShimsDivCeil for u16 {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + Self::from(u8::from(has_remainder))
      }
    }
    impl StdShimsDivCeil for u32 {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + Self::from(u8::from(has_remainder))
      }
    }
    impl StdShimsDivCeil for u64 {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + Self::from(u8::from(has_remainder))
      }
    }
    impl StdShimsDivCeil for u128 {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + Self::from(u8::from(has_remainder))
      }
    }
    impl StdShimsDivCeil for usize {
      fn div_ceil(self, denominator: Self) -> Self {
        let quotient = self / denominator;
        let has_remainder = (quotient * denominator) != self;
        quotient + Self::from(u8::from(has_remainder))
      }
    }
  }

  // Shim `io::Error::other`
  #[cfg(feature = "std")]
  #[rustversion::before(1.74)]
  #[doc(hidden)]
  pub trait StdShimsIoErrorOther {
    fn other<E>(error: E) -> Self
    where
      E: Into<Box<dyn std::error::Error + Send + Sync>>;
  }
  #[cfg(feature = "std")]
  #[rustversion::before(1.74)]
  impl StdShimsIoErrorOther for std::io::Error {
    fn other<E>(error: E) -> Self
    where
      E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
      std::io::Error::new(std::io::ErrorKind::Other, error)
    }
  }
}
