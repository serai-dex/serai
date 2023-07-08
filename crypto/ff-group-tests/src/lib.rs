#![allow(clippy::tests_outside_test_module)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

/// Tests for the Field trait.
pub mod field;
/// Tests for the PrimeField and PrimeFieldBits traits.
pub mod prime_field;

/// Tests for the Group and GroupEncoding traits.
pub mod group;
