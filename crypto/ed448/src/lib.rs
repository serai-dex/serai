#![allow(clippy::tests_outside_test_module)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

#[macro_use]
mod backend;

mod scalar;
pub use scalar::Scalar;

mod field;
pub use field::FieldElement;

mod point;
pub use point::Point;
