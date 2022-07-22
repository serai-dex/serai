use ink_lang::{EnvAccess, codegen::StaticEnv};

use openbrush::{modifier_definition, contracts::psp22::PSP22Error};

use crate::SeraiEnvironment;

pub enum InherentError {
  NotInherentTransaction,
}

impl From<InherentError> for PSP22Error {
  fn from(_: InherentError) -> PSP22Error {
    PSP22Error::Custom("not called by inherent transaction".to_string())
  }
}

/// Throws if not called inside an inherent transaction.
#[modifier_definition]
pub fn only_inherent<
  T: StaticEnv<EnvAccess = EnvAccess<'static, SeraiEnvironment>>,
  F: FnOnce(&mut T) -> Result<R, E>,
  R,
  E: From<InherentError>,
>(
  instance: &mut T,
  body: F,
) -> Result<R, E> {
  // inherent either needs to be single-use OR we need this check in wasm
  // It's much simpler to do this here
  if (!T::env().extension().inherent()) || (!T::env().caller_is_origin()) {
    return Err(E::from(InherentError::NotInherentTransaction));
  }

  body(instance)
}
