#![cfg_attr(not(feature = "std"), no_std)]
#![feature(min_specialization)]

#[openbrush::contract(env = serai_extension::SeraiEnvironment)]
pub mod asset {
  use ink_prelude::string::String;
  use ink_storage::traits::SpreadAllocate;

  use openbrush::contracts::psp22::*;
  use openbrush::contracts::psp22::extensions::metadata::*;
  use openbrush::contracts::psp22::extensions::mintable::*;

  use serai_extension::only_inherent::only_inherent;

  #[ink(storage)]
  #[derive(Default, SpreadAllocate, PSP22Storage, PSP22MetadataStorage)]
  pub struct SeraiAsset {
    #[PSP22StorageField]
    psp22: PSP22Data,
    #[PSP22MetadataStorageField]
    metadata: PSP22MetadataData,
  }

  impl PSP22 for SeraiAsset {}
  impl PSP22Metadata for SeraiAsset {}

  impl PSP22Mintable for SeraiAsset {
    #[ink(message)]
    #[openbrush::modifiers(only_inherent)]
    fn mint(&mut self, account: AccountId, amount: Balance) -> Result<(), PSP22Error> {
      // TODO: Check there's room in the bond to mint this
      // TODO: Transfer and call account on mint
      self._mint(account, amount)
    }
  }

  impl SeraiAsset {
    #[ink(constructor)]
    pub fn new(name: String, symbol: String) -> Self {
      ink_lang::codegen::initialize_contract(|instance: &mut SeraiAsset| {
        instance.metadata.name = Some(name);
        instance.metadata.symbol = Some(symbol);
        instance.metadata.decimals = 8;
      })
    }
  }
}
