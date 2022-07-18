#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
use ink_env::{Environment, DefaultEnvironment, AccountId};

#[ink::chain_extension]
pub trait SeraiExtension {
  type ErrorCode = ();

  /// Returns the amount of active validators on the current chain.
  #[ink(extension = 0, handle_status = false, returns_result = false)]
  fn active_validators_len() -> u16;

  /// Returns the ID for the current validator set for the current chain.
  // TODO: Decide if this should be an increasing unsigned integer instead of a hash.
  #[ink(extension = 1, handle_status = false, returns_result = false)]
  fn validator_set_id() -> [u8; 32];

  /// Returns if the specified account is an active validator for the current chain.
  #[ink(extension = 2, handle_status = false, returns_result = false)]
  fn is_active_validator(account: &AccountId) -> bool;
}

pub struct SeraiEnvironment;
impl Environment for SeraiEnvironment {
  const MAX_EVENT_TOPICS: usize = <DefaultEnvironment as Environment>::MAX_EVENT_TOPICS;

  type AccountId = <DefaultEnvironment as Environment>::AccountId;
  type Balance = <DefaultEnvironment as Environment>::Balance;
  type Hash = <DefaultEnvironment as Environment>::Hash;
  type BlockNumber = <DefaultEnvironment as Environment>::BlockNumber;
  type Timestamp = <DefaultEnvironment as Environment>::Timestamp;

  type ChainExtension = SeraiExtension;
}
