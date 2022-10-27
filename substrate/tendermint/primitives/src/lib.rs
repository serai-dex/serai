#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::sr25519::Public;

trait TendermintApi {
  fn validators() -> Vec<Public>;
}
