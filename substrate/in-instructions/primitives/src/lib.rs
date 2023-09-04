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

use serai_primitives::{
  BlockHash, Balance, NetworkId, SeraiAddress, ExternalAddress, Coin, Amount, pallet_address,
};

mod shorthand;
pub use shorthand::*;

pub const MAX_BATCH_SIZE: usize = 25_000; // ~25kb

// This is just an account that will make ops in behalf of users for the
// in instructions that is coming in. Not to be confused with in_instructions pallet.
// in_instructions are a pallet(a module) and that is just and account.
pub const IN_INSTRUCTION_EXECUTOR: SeraiAddress = pallet_address(b"InInstructionExecutor");

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum InInstruction {
  Transfer(SeraiAddress),
  Dex(DexCall),
}

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum DexCall {
  // address to sent the lp tokens to
  AddLiquidity(SeraiAddress),
  // to_coin, to_address, min_out_amount. TODO: sync with docs.
  Swap(Coin, ExternalAddress, Amount),
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
pub fn batch_message(batch: &Batch) -> Vec<u8> {
  [b"InInstructions-batch".as_ref(), &batch.encode()].concat()
}
