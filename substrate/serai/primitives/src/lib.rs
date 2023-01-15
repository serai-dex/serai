#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::sr25519::{Public, Signature as RistrettoSignature};

mod amount;
pub use amount::*;

mod coins;
pub use coins::*;

pub type PublicKey = Public;
pub type NativeAddress = PublicKey;
pub type Signature = RistrettoSignature;

/// The type used to identify block numbers.
// Doesn't re-export TendermintMachine due to traits.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlockNumber(pub u32);
impl From<u32> for BlockNumber {
  fn from(number: u32) -> BlockNumber {
    BlockNumber(number)
  }
}
