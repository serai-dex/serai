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

pub fn test_register() {
  struct ExtensionLen;
  impl ink_env::test::ChainExtension for ExtensionLen {
    fn func_id(&self) -> u32 {
      0
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      scale::Encode::encode_to(&5u16, output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionLen);

  struct ExtensionId;
  impl ink_env::test::ChainExtension for ExtensionId {
    fn func_id(&self) -> u32 {
      1
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      scale::Encode::encode_to(&[0xffu8; 32], output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionId);

  struct ExtensionActive;
  impl ink_env::test::ChainExtension for ExtensionActive {
    fn func_id(&self) -> u32 {
      2
    }

    fn call(&mut self, input: &[u8], output: &mut Vec<u8>) -> u32 {
      use scale::Decode;
      let potential = AccountId::decode(&mut &input[1 ..]).unwrap(); // TODO: Why is this 1 ..?

      let mut presence = false;
      for validator in [
        AccountId::from([1; 32]),
        AccountId::from([2; 32]),
        AccountId::from([3; 32]),
        AccountId::from([4; 32]),
        AccountId::from([5; 32])
      ].clone() {
        if potential == validator {
          presence = true;
        }
      }
      scale::Encode::encode_to(&presence, output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionActive);
}
