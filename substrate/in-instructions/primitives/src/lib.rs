#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_application_crypto::sr25519::Signature;

#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;
use sp_runtime::RuntimeDebug;

use serai_primitives::{BlockHash, Balance, NetworkId, SeraiAddress, ExternalAddress, Data};

mod shorthand;
pub use shorthand::*;

pub const MAX_BATCH_SIZE: usize = 25_000; // ~25kb

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum InInstruction {
  Transfer(SeraiAddress),
  Dex(Data),
}

#[derive(
  Clone,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  Encode,
  Decode,
  MaxEncodedLen,
  TypeInfo,
  RuntimeDebug,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct RefundableInInstruction {
  pub origin: Option<ExternalAddress>,
  pub instruction: InInstruction,
}

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct InInstructionWithBalance {
  pub instruction: InInstruction,
  pub balance: Balance,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct Batch {
  pub network: NetworkId,
  pub id: u32,
  pub block: BlockHash,
  pub instructions: Vec<InInstructionWithBalance>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TypeInfo, RuntimeDebug)]
pub struct SignedBatch {
  pub batch: Batch,
  pub signature: Signature,
}

#[cfg(feature = "std")]
impl Zeroize for SignedBatch {
  fn zeroize(&mut self) {
    self.batch.zeroize();
    self.signature.as_mut().zeroize();
  }
}

// TODO: Make this an associated method?
/// The message for the batch signature.
pub fn batch_message(is_first_batch_of_set: bool, batch: &Batch) -> Vec<u8> {
  [b"InInstructions-batch".as_ref(), &(is_first_batch_of_set, batch).encode()].concat()
}
