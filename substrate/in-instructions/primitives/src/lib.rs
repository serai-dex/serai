#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_application_crypto::sr25519::Signature;

#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;
use sp_runtime::RuntimeDebug;

#[rustfmt::skip]
use serai_primitives::{BlockHash, Balance, NetworkId, SeraiAddress, ExternalAddress, system_address};

mod shorthand;
pub use shorthand::*;

pub const MAX_BATCH_SIZE: usize = 25_000; // ~25kb

// This is the account which will be the origin for add liquidity instructions.
pub const ADD_LIQUIDITY_ACCOUNT: SeraiAddress = system_address(b"add-liquidty-account");

// This is the account which will be the origin for swap intructions.
pub const SWAP_ACCOUNT: SeraiAddress = system_address(b"swap-account");

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OutAddress {
  Serai(SeraiAddress),
  External(ExternalAddress),
}

impl OutAddress {
  pub fn is_native(&self) -> bool {
    matches!(self, Self::Serai(_))
  }

  pub fn as_native(self) -> Option<SeraiAddress> {
    match self {
      Self::Serai(addr) => Some(addr),
      _ => None,
    }
  }

  pub fn as_external(self) -> Option<ExternalAddress> {
    match self {
      Self::External(addr) => Some(addr),
      Self::Serai(_) => None,
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DexCall {
  // address to send the lp tokens to
  // TODO: Update this per documentation/Shorthand
  SwapAndAddLiquidity(SeraiAddress),
  // minimum out balance and out address
  Swap(Balance, OutAddress),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InInstruction {
  Transfer(SeraiAddress),
  Dex(DexCall),
  GenesisLiquidity(SeraiAddress),
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefundableInInstruction {
  pub origin: Option<ExternalAddress>,
  pub instruction: InInstruction,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InInstructionWithBalance {
  pub instruction: InInstruction,
  pub balance: Balance,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Batch {
  pub network: NetworkId,
  pub id: u32,
  pub block: BlockHash,
  pub instructions: Vec<InInstructionWithBalance>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedBatch {
  pub batch: Batch,
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "serai_primitives::borsh_serialize_signature",
      deserialize_with = "serai_primitives::borsh_deserialize_signature"
    )
  )]
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
