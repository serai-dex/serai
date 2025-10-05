#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![expect(clippy::cast_possible_truncation)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, DecodeWithMemTracking, MaxEncodedLen};

use serai_primitives::{ExternalBalance, SeraiAddress, ExternalAddress, system_address};

pub const FEE_ACCOUNT: SeraiAddress = system_address(b"Coins-fees");

// TODO: Replace entirely with just Address
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutInstruction {
  pub address: ExternalAddress,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutInstructionWithBalance {
  pub instruction: OutInstruction,
  pub balance: ExternalBalance,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Destination {
  Native(SeraiAddress),
  External(OutInstruction),
}

#[test]
fn address() {
  use sp_runtime::traits::TrailingZeroInput;
  assert_eq!(
    FEE_ACCOUNT,
    SeraiAddress::decode(&mut TrailingZeroInput::new(b"Coins-fees")).unwrap()
  );
}
