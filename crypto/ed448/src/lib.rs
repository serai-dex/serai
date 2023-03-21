#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]
#![doc = include_str!("../README.md")]

mod backend;

mod scalar;
pub use scalar::Scalar;

mod field;
pub use field::FieldElement;

mod point;
pub use point::Point;
