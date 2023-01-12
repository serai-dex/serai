use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

use serai_primitives::NativeAddress;

use crate::{MAX_DATA_LEN, ExternalAddress};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Application {
  DEX,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ApplicationCall {
  application: Application,
  data: BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Target {
  Application(ApplicationCall),
  Address(NativeAddress),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct InInstruction {
  pub origin: ExternalAddress,
  pub target: Target,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ExternalInInstruction {
  origin: Option<ExternalAddress>,
  target: Target,
}

impl TryFrom<ExternalInInstruction> for InInstruction {
  type Error = &'static str;
  fn try_from(external: ExternalInInstruction) -> Result<InInstruction, &'static str> {
    Ok(InInstruction { origin: external.origin.ok_or("no origin")?, target: external.target })
  }
}
