#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use serai_primitives::{Balance, SeraiAddress, ExternalAddress, Data, pallet_address};

pub const ADDRESS: SeraiAddress = pallet_address(b"Tokens");

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct OutInstruction {
  pub address: ExternalAddress,
  pub data: Option<Data>,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct OutInstructionWithBalance {
  pub instruction: OutInstruction,
  pub balance: Balance,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub enum Destination {
  Native(SeraiAddress),
  External(OutInstruction),
}

#[test]
fn address() {
  use sp_runtime::traits::TrailingZeroInput;
  assert_eq!(ADDRESS, SeraiAddress::decode(&mut TrailingZeroInput::new(b"Tokens")).unwrap());
}
