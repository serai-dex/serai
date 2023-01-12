use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(not(feature = "std"))]
use sp_std::Debug;
use sp_core::{ConstU32, bounded::BoundedVec};

use serai_primitives::NativeAddress;

use crate::{MAX_DATA_LEN, ExternalAddress};

#[cfg(feature = "std")]
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub enum Destination {
  Native(NativeAddress),
  External(ExternalAddress),
}

#[cfg(not(feature = "std"))]
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub enum Destination {
  Native(NativeAddress),
  External(ExternalAddress),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct OutInstruction {
  destination: Destination,
  data: Option<BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>>,
}
