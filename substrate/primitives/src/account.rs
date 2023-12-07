#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_core::sr25519::Public;
pub use sp_core::sr25519::Signature;
#[cfg(feature = "std")]
use sp_core::{Pair as PairTrait, sr25519::Pair};

use sp_runtime::traits::{LookupError, Lookup, StaticLookup};

pub type PublicKey = Public;

#[cfg(feature = "borsh")]
pub fn borsh_serialize_public<W: borsh::io::Write>(
  public: &Public,
  writer: &mut W,
) -> Result<(), borsh::io::Error> {
  borsh::BorshSerialize::serialize(&public.0, writer)
}

#[cfg(feature = "borsh")]
pub fn borsh_deserialize_public<R: borsh::io::Read>(
  reader: &mut R,
) -> Result<Public, borsh::io::Error> {
  let public: [u8; 32] = borsh::BorshDeserialize::deserialize_reader(reader)?;
  Ok(Public(public))
}

#[cfg(feature = "borsh")]
pub fn borsh_serialize_signature<W: borsh::io::Write>(
  signature: &Signature,
  writer: &mut W,
) -> Result<(), borsh::io::Error> {
  borsh::BorshSerialize::serialize(&signature.0, writer)
}

#[cfg(feature = "borsh")]
pub fn borsh_deserialize_signature<R: borsh::io::Read>(
  reader: &mut R,
) -> Result<Signature, borsh::io::Error> {
  let signature: [u8; 64] = borsh::BorshDeserialize::deserialize_reader(reader)?;
  Ok(Signature(signature))
}

// TODO: Remove this for solely Public?
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SeraiAddress(pub [u8; 32]);
impl SeraiAddress {
  pub fn new(key: [u8; 32]) -> SeraiAddress {
    SeraiAddress(key)
  }
}

impl From<[u8; 32]> for SeraiAddress {
  fn from(key: [u8; 32]) -> SeraiAddress {
    SeraiAddress(key)
  }
}

impl From<PublicKey> for SeraiAddress {
  fn from(key: PublicKey) -> SeraiAddress {
    SeraiAddress(key.0)
  }
}

impl From<SeraiAddress> for PublicKey {
  fn from(address: SeraiAddress) -> PublicKey {
    PublicKey::from_raw(address.0)
  }
}

#[cfg(feature = "std")]
impl std::fmt::Display for SeraiAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // TODO: Bech32
    write!(f, "{:?}", self.0)
  }
}

#[cfg(feature = "std")]
pub fn insecure_pair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

pub struct AccountLookup;
impl Lookup for AccountLookup {
  type Source = SeraiAddress;
  type Target = PublicKey;
  fn lookup(&self, source: SeraiAddress) -> Result<PublicKey, LookupError> {
    Ok(PublicKey::from_raw(source.0))
  }
}
impl StaticLookup for AccountLookup {
  type Source = SeraiAddress;
  type Target = PublicKey;
  fn lookup(source: SeraiAddress) -> Result<PublicKey, LookupError> {
    Ok(source.into())
  }
  fn unlookup(source: PublicKey) -> SeraiAddress {
    source.into()
  }
}

pub const fn system_address(pallet: &'static [u8]) -> SeraiAddress {
  let mut address = [0; 32];
  let mut set = false;
  // Implement a while loop since we can't use a for loop
  let mut i = 0;
  while i < pallet.len() {
    address[i] = pallet[i];
    if address[i] != 0 {
      set = true;
    }
    i += 1;
  }
  // Make sure this address isn't the identity point
  // Doesn't do address != [0; 32] since that's not const
  assert!(set, "address is the identity point");
  SeraiAddress(address)
}
