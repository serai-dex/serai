#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::sr25519::Public;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
  pub trait TendermintApi {
    /// Current session number. A session is NOT a fixed length of blocks, yet rather a continuous
    /// set of validators.
    fn current_session() -> u32;

    /// Current validators.
    fn validators() -> Vec<Public>;
  }
}
