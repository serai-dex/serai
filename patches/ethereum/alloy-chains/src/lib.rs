#![no_std]

use core::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum NamedChain {}
impl NamedChain {
  pub const fn average_blocktime_hint(&self) -> Option<Duration> {
    None
  }
}
