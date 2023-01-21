#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use serai_primitives::{SeraiAddress, ExternalAddress, Data, pallet_address};

pub const ADDRESS: SeraiAddress = pallet_address(b"Tokens");

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum OutInstruction {
  Native(SeraiAddress),
  External(ExternalAddress, Data),
}

#[test]
fn address() {
  use sp_runtime::traits::TrailingZeroInput;
  assert_eq!(ADDRESS, SeraiAddress::decode(&mut TrailingZeroInput::new(b"Tokens")).unwrap());
}
