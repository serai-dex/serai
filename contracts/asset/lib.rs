#![cfg_attr(not(feature = "std"), no_std)]
#![feature(min_specialization)]

#[openbrush::contract(env = serai_extension::SeraiEnvironment)]
pub mod asset {
  use ink_prelude::string::String;
  use ink_storage::traits::SpreadAllocate;
  use ink_env::{
    Error, CallFlags,
    call::{Selector, ExecutionInput, Call, build_call},
  };

  use openbrush::contracts::psp22::*;
  use openbrush::contracts::psp22::extensions::metadata::*;

  use serai_extension::{SeraiEnvironment, only_inherent::only_inherent};

  struct RawCall<'a>(&'a [u8]);
  impl<'a> scale::Encode for RawCall<'a> {
    fn encode_to<T: ?Sized + scale::Output>(&self, dest: &mut T) {
      dest.write(self.0);
    }
  }

  #[ink(event)]
  pub struct NativeTransfer {
    #[ink(topic)]
    from: AccountId,
    #[ink(topic)]
    to: Vec<u8>,
    // TODO: Replace Balance, which is DefaultEnvironment's u128, with u64
    amount: Balance,
    data: Option<Vec<u8>>,
  }

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

  impl SeraiAsset {
    #[ink(constructor)]
    pub fn new(name: String, symbol: String) -> Self {
      ink_lang::codegen::initialize_contract(|instance: &mut SeraiAsset| {
        instance.metadata.name = Some(name);
        instance.metadata.symbol = Some(symbol);
        instance.metadata.decimals = 8;
      })
    }

    #[ink(message)]
    #[openbrush::modifiers(only_inherent)]
    pub fn mint(
      &mut self,
      account: AccountId,
      amount: Balance,
      instruction: Vec<u8>,
    ) -> Result<(), PSP22Error> {
      // TODO: Check there's room in the bond to mint this
      self._mint(account, amount)?;
      match build_call::<SeraiEnvironment>()
        .call_type(Call::new().callee(account))
        .call_flags(CallFlags::default().set_allow_reentry(true))
        .exec_input(
          ExecutionInput::new(Selector::new(
            instruction[.. 4]
              .try_into()
              .map_err(|_| PSP22Error::Custom("invalid in instruction".to_string()))?,
          ))
          .push_arg(RawCall(&instruction[4 ..])),
        )
        .returns::<()>()
        .fire()
      {
        Ok(_) => Ok(()),
        Err(Error::NotCallable) => Ok(()),
        Err(_) => Err(PSP22Error::Custom("invalid in instruction".to_string())),
      }
    }

    #[ink(message)]
    pub fn native_transfer(
      &mut self,
      to: Vec<u8>,
      amount: Balance,
      data: Option<Vec<u8>>,
    ) -> Result<(), PSP22Error> {
      self._burn_from(self.env().caller(), amount)?;
      self.env().emit_event(NativeTransfer { from: self.env().caller(), to, amount, data });
      Ok(())
    }
  }
}
