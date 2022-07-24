#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
use ink_env::{Environment, DefaultEnvironment, AccountId};

pub mod only_inherent;

pub type Curve = u16;
pub type Coin = u32;
pub type GlobalValidatorSetId = u32;
pub type ValidatorSetIndex = u8;
pub type Key = Vec<u8>;

#[ink::chain_extension]
pub trait SeraiExtension {
  type ErrorCode = ();

  /// Returns if the current transaction is an inherent transaction or not.
  #[ink(extension = 0, handle_status = false, returns_result = false)]
  fn inherent() -> bool;

  /// Returns the ID for the current global validator set.
  #[ink(extension = 1, handle_status = false, returns_result = false)]
  fn global_validator_set_id() -> GlobalValidatorSetId;

  /// Returns the amount of active validator sets within the global validator set.
  #[ink(extension = 2, handle_status = false, returns_result = false)]
  fn validator_sets() -> u8;

  /// Returns the amount of key shares used within the specified validator set.
  #[ink(extension = 3, handle_status = false, returns_result = false)]
  fn validator_set_shares(set: ValidatorSetIndex) -> u16;

  /// Returns the validator set the specified account is in, along with their amount of shares in
  /// that validator set, if they are in a current validator
  #[ink(extension = 4, handle_status = false, returns_result = false)]
  fn active_validator(account: &AccountId) -> Option<(ValidatorSetIndex, u16)>;
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

pub fn test_validators() -> Vec<AccountId> {
  vec![
    AccountId::from([1; 32]),
    AccountId::from([2; 32]),
    AccountId::from([3; 32]),
    AccountId::from([4; 32]),
    AccountId::from([5; 32]),
  ]
}

pub fn test_register() {
  struct ExtensionInherent;
  impl ink_env::test::ChainExtension for ExtensionInherent {
    fn func_id(&self) -> u32 {
      0
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      // Say it's an inherent so inherent-only functions can be called
      scale::Encode::encode_to(&true, output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionInherent);

  struct ExtensionId;
  impl ink_env::test::ChainExtension for ExtensionId {
    fn func_id(&self) -> u32 {
      1
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      // Non-0 global validator set ID
      scale::Encode::encode_to(&1u32, output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionId);

  struct ExtensionSets;
  impl ink_env::test::ChainExtension for ExtensionSets {
    fn func_id(&self) -> u32 {
      2
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      // 1 validator set
      scale::Encode::encode_to(&1u8, output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionSets);

  struct ExtensionShares;
  impl ink_env::test::ChainExtension for ExtensionShares {
    fn func_id(&self) -> u32 {
      3
    }

    fn call(&mut self, _: &[u8], output: &mut Vec<u8>) -> u32 {
      // 1 key share per validator
      scale::Encode::encode_to(&u16::try_from(test_validators().len()).unwrap(), output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionShares);

  struct ExtensionActive;
  impl ink_env::test::ChainExtension for ExtensionActive {
    fn func_id(&self) -> u32 {
      4
    }

    fn call(&mut self, input: &[u8], output: &mut Vec<u8>) -> u32 {
      use scale::Decode;
      let potential = AccountId::decode(&mut &input[1 ..]).unwrap(); // TODO: Why is this [1 ..]?

      let mut presence = false;
      for validator in test_validators() {
        if potential == validator {
          presence = true;
        }
      }
      // Validator set 0, 1 key share
      scale::Encode::encode_to(&Some((0u8, 1u16)).filter(|_| presence), output);
      0
    }
  }
  ink_env::test::register_chain_extension(ExtensionActive);
}
