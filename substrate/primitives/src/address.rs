use core::convert::AsRef;
use alloc::vec::Vec;

use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::{sr25519::Public, ConstU32, bounded::BoundedVec};

/*
  We only use a single HRP across all networks. This follows Serai's general practice. Addresses
  for external networks are represented in binary, without network information. to minimize
  bandwidth and reduce potential for malleability.

  This is continued here not solely to be a continuance, yet also with appreciation for the
  simplicity. This does make it easier for users to make the mistake of using a testnet address
  where they intended to use a mainnet address (and vice-versa). Since public keys are usable on
  any network, this should have limited impact and accordingly not be the end of the world.

  There's also precedent for this due to Ethereum (though they do have a somewhat-adopted checksum
  scheme to encode the network regardless).
*/
const HUMAN_READABLE_PART: bech32::Hrp = bech32::Hrp::parse_unchecked("sri");

/// The address for an account on Serai.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
pub struct SeraiAddress(pub [u8; 32]);

// These share encodings as 32-byte arrays
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<Public> for SeraiAddress {}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<Public> for &SeraiAddress {}

impl SeraiAddress {
  /// Generate an address for use by the system.
  ///
  /// The returned addresses MAY be valid points. This assumes its infeasible to find the discrete
  /// logarithm for a point whose representation has a known Blake2b-256 preimage.
  // The alternative would be to massage this until its not a valid point, which isn't worth the
  // computational expense as this should be a hard problem for outputs which happen to be points.
  pub fn system(label: &[u8]) -> Self {
    Self(sp_core::blake2_256(label))
  }
}

impl From<Public> for SeraiAddress {
  fn from(key: Public) -> Self {
    // The encoding of a Ristretto point is the encoding of its address
    Self(key.0)
  }
}
/*
  A `SeraiAddress` may not be a valid public key. The `sr25519::Public` is not a checked public
  key, solely bytes alleged to be a public key, which any `SeraiAddress` converted into a `Public`
  is also alleged to be.
*/
impl From<SeraiAddress> for Public {
  fn from(address: SeraiAddress) -> Self {
    Self::from_raw(address.0)
  }
}

impl From<crate::crypto::Public> for SeraiAddress {
  fn from(key: crate::crypto::Public) -> Self {
    Public::from(key).into()
  }
}
impl From<SeraiAddress> for crate::crypto::Public {
  fn from(address: SeraiAddress) -> Self {
    Public::from(address).into()
  }
}

// We use Bech32m to encode addresses
impl core::fmt::Display for SeraiAddress {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match bech32::encode_to_fmt::<bech32::Bech32m, _>(f, HUMAN_READABLE_PART, &self.0) {
      Ok(()) => Ok(()),
      Err(bech32::EncodeError::TooLong(_)) => {
        unreachable!("32 bytes exceeded bech32 length limit?")
      }
      Err(bech32::EncodeError::Fmt(e)) => Err(e),
      // bech32::EncodeError is non-exhaustive
      Err(_) => Err(core::fmt::Error),
    }
  }
}

/// An error from decoding an address.
pub enum DecodeError {
  /// The Bech32m encoding was invalid.
  InvalidBech32m,
  /// The Bech32m Human-Readable Part was distinct.
  DistinctHrp,
  /// The encoded data's length was wrong.
  InvalidLength,
}

impl core::str::FromStr for SeraiAddress {
  type Err = DecodeError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // We drop bech32's error to remain opaque to the implementation
    let decoded = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s)
      .map_err(|_| DecodeError::InvalidBech32m)?;
    if decoded.hrp() != HUMAN_READABLE_PART {
      Err(DecodeError::DistinctHrp)?;
    }

    let mut res = Self([0; 32]);
    let mut iter = decoded.byte_iter();
    for i in 0 .. 32 {
      let Some(byte) = iter.next() else { Err(DecodeError::InvalidLength)? };
      res.0[i] = byte;
    }
    if iter.next().is_some() {
      Err(DecodeError::InvalidLength)?;
    }
    Ok(res)
  }
}

/// An address for an external network.
#[derive(Clone, PartialEq, Eq, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
pub struct ExternalAddress(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  BoundedVec<u8, ConstU32<{ ExternalAddress::MAX_LEN }>>,
);

impl ExternalAddress {
  /// The maximum length for an `ExternalAddress`.
  pub const MAX_LEN: u32 = 512;
}

/// An error when converting from a `Vec`.
#[derive(Debug)]
pub enum FromVecError {
  /// The source `Vec` was too long to be converted.
  TooLong,
}

impl TryFrom<Vec<u8>> for ExternalAddress {
  type Error = FromVecError;
  fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
    vec.try_into().map(ExternalAddress).map_err(|_| FromVecError::TooLong)
  }
}
impl From<ExternalAddress> for Vec<u8> {
  fn from(ext: ExternalAddress) -> Vec<u8> {
    ext.0.into_inner()
  }
}

impl AsRef<[u8]> for ExternalAddress {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl zeroize::Zeroize for ExternalAddress {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize();
  }
}
