#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{
  H256,
  sr25519::{Public, Signature as RistrettoSignature},
};

mod amount;
pub use amount::*;

mod coins;
pub use coins::*;

pub type PublicKey = Public;
pub type SeraiAddress = PublicKey;
pub type Signature = RistrettoSignature;

/// The type used to identify block numbers.
// Doesn't re-export tendermint-machine's due to traits.
#[derive(
  Clone, Copy, Default, PartialEq, Eq, Hash, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlockNumber(pub u32);
impl From<u32> for BlockNumber {
  fn from(number: u32) -> BlockNumber {
    BlockNumber(number)
  }
}

/// The type used to identify block hashes.
// This may not be universally compatible
// If a block exists with a hash which isn't 32-bytes, it can be hashed into a value with 32-bytes
// This would require the processor to maintain a mapping of 32-byte IDs to actual hashes, which
// would be fine
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlockHash(pub [u8; 32]);

impl AsRef<[u8]> for BlockHash {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl From<[u8; 32]> for BlockHash {
  fn from(hash: [u8; 32]) -> BlockHash {
    BlockHash(hash)
  }
}

impl From<H256> for BlockHash {
  fn from(hash: H256) -> BlockHash {
    BlockHash(hash.into())
  }
}
