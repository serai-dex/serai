use core::convert::AsRef;

use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::sr25519::Public;

mod external;
pub use external::*;

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
///
/// The 32-byte blob within it is used as an identifier for the account and when verifying
/// signatures, a commitment to the signing key for the account.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct SeraiAddress(pub [u8; 32]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(SeraiAddress);

#[cfg(feature = "scale")]
impl scale::EncodeLike<Public> for SeraiAddress {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<Public> for &SeraiAddress {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<SeraiAddress> for Public {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<SeraiAddress> for &Public {}

impl SeraiAddress {
  /// Generate an address for use by the system.
  ///
  /// The returned addresses MAY be valid points. This assumes its infeasible to find the discrete
  /// logarithm for a point whose representation has a known Blake2b-256 preimage.
  // The alternative would be to massage this until its not a valid point, which isn't worth the
  // computational expense as this should be a hard problem for outputs which happen to be points.
  pub fn system(label: impl AsRef<[u8]>) -> Self {
    Self(sp_core::blake2_256(label.as_ref()))
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
      // [`bech32::EncodeError`] is non-exhaustive
      Err(_) => Err(core::fmt::Error),
    }
  }
}

/// An error from an address.
#[derive(Debug)]
pub enum AddressError {
  /// The Bech32m encoding was invalid.
  InvalidBech32m,
  /// The Bech32m Human-Readable Part was distinct.
  DistinctHrp,
  /// The encoded data's length was wrong.
  InvalidLength,
}

impl core::str::FromStr for SeraiAddress {
  type Err = AddressError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // We drop `bech32`'s error to remain opaque to the implementation
    let decoded = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s)
      .map_err(|_| AddressError::InvalidBech32m)?;
    if decoded.hrp() != HUMAN_READABLE_PART {
      Err(AddressError::DistinctHrp)?;
    }

    let mut res = Self([0; 32]);
    let mut iter = decoded.byte_iter();
    for i in 0 .. 32 {
      let Some(byte) = iter.next() else { Err(AddressError::InvalidLength)? };
      res.0[i] = byte;
    }
    if iter.next().is_some() {
      Err(AddressError::InvalidLength)?;
    }
    Ok(res)
  }
}

#[test]
fn address() {
  use core::str::FromStr as _;
  use alloc::string::ToString as _;
  use rand_core::{RngCore as _, OsRng};

  // Check the HRP is valid
  bech32::Hrp::parse(HUMAN_READABLE_PART.as_str()).unwrap();

  // Fuzz valid address
  for _ in 0 .. 100 {
    let mut address = [0; 32];
    OsRng.fill_bytes(&mut address);
    let encoding = bech32::encode::<bech32::Bech32m>(HUMAN_READABLE_PART, &address).unwrap();
    let address = SeraiAddress(address);
    assert_eq!(address.to_string(), encoding);
    assert_eq!(SeraiAddress::from_str(&encoding).unwrap(), address);
    assert_eq!(&encoding.as_bytes()[.. 4], b"sri1");
  }

  // Test a distinct HRP
  assert!(matches!(
    SeraiAddress::from_str(
      &bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("dif").unwrap(), &[0; 32]).unwrap()
    )
    .unwrap_err(),
    AddressError::DistinctHrp
  ));

  // Test a distinct length
  assert!(matches!(
    SeraiAddress::from_str(
      &bech32::encode::<bech32::Bech32m>(HUMAN_READABLE_PART, &[0; 31]).unwrap()
    )
    .unwrap_err(),
    AddressError::InvalidLength
  ));
  assert!(matches!(
    SeraiAddress::from_str(
      &bech32::encode::<bech32::Bech32m>(HUMAN_READABLE_PART, &[0; 33]).unwrap()
    )
    .unwrap_err(),
    AddressError::InvalidLength
  ));
}
