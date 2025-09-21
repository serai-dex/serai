#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![expect(clippy::cast_possible_truncation)]

use scale::{Encode, Decode, DecodeWithMemTracking, MaxEncodedLen};

use serai_primitives::ExternalNetworkId;

#[derive(
  Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(zeroize::Zeroize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalId {
  Retirement([u8; 32]),
  Halt(ExternalNetworkId),
}
