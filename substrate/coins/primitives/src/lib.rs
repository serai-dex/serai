#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use serai_primitives::{Balance, SeraiAddress, ExternalAddress, Data, pallet_address};

pub const FEE_ACCOUNT: SeraiAddress = pallet_address(b"FeeAccount");

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct OutInstruction {
  pub address: ExternalAddress,
  pub data: Option<Data>,
}

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct OutInstructionWithBalance {
  pub instruction: OutInstruction,
  pub balance: Balance,
}

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum Destination {
  Native(SeraiAddress),
  External(OutInstruction),
}

#[test]
fn address() {
  use sp_runtime::traits::TrailingZeroInput;
  assert_eq!(
    FEE_ACCOUNT,
    SeraiAddress::decode(&mut TrailingZeroInput::new(b"FeeAccount")).unwrap()
  );
}
