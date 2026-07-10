#![no_std]

use core::fmt;

#[derive(Clone, Copy, Debug)]
pub enum EthereumHardfork {
  Paris,
  Cancun,
  Shanghai,
  Prague,
}

impl fmt::Display for EthereumHardfork {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

#[test]
fn to_string() {
  extern crate std;
  use std::string::ToString;

  assert_eq!(EthereumHardfork::Paris.to_string(), "Paris");
  assert_eq!(EthereumHardfork::Cancun.to_string(), "Cancun");
  assert_eq!(EthereumHardfork::Shanghai.to_string(), "Shanghai");
  assert_eq!(EthereumHardfork::Prague.to_string(), "Prague");
}
