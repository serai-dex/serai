use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

use serai_primitives::NativeAddress;

use crate::{MAX_DATA_LEN, ExternalAddress};

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Destination {
  Native(NativeAddress),
  External(ExternalAddress),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct OutInstruction {
  destination: Destination,
  data: Option<BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>>,
}
