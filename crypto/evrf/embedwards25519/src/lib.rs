#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[macro_use]
mod backend;

mod scalar;
pub use scalar::Scalar;

pub use dalek_ff_group::Scalar as FieldElement;

mod point;
pub use point::Point;
