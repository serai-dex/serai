#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;
use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockNumber, BlockHash, SeraiAddress, ExternalAddress, Data, WithAmount};

mod shorthand;
pub use shorthand::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub enum Application {
  DEX,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct ApplicationCall {
  application: Application,
  data: Data,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub enum InInstruction {
  Transfer(SeraiAddress),
  Call(ApplicationCall),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct RefundableInInstruction {
  pub origin: Option<ExternalAddress>,
  pub instruction: InInstruction,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct Batch {
  pub id: BlockHash,
  pub instructions: Vec<WithAmount<InInstruction>>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct Update {
  // Coin's latest block number
  pub block_number: BlockNumber,
  pub batches: Vec<Batch>,
}

// None if the current block producer isn't operating over this coin or otherwise failed to get
// data
pub type Updates = Vec<Option<Update>>;
