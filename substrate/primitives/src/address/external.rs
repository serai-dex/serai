use core::convert::AsRef;
use alloc::vec::Vec;

use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

/// An address for an external network.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExternalAddress(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  BoundedVec<u8, ConstU32<{ ExternalAddress::MAX_LEN }>>,
);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalAddress);

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

impl Zeroize for ExternalAddress {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize();
  }
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};

  // Fuzz test various `ExternalAddress`s
  for _ in 0 .. 100 {
    let mut vec =
      vec![0; usize::try_from(OsRng.next_u64() % u64::from(ExternalAddress::MAX_LEN)).unwrap()];
    OsRng.fill_bytes(&mut vec);
    let address = ExternalAddress::try_from(vec)
      .expect("`Vec` whose length was less than bound couldn't convert into `ExternalAddress`");

    assert_eq!(
      ExternalAddress::deserialize_reader(&mut borsh::to_vec(&address).unwrap().as_slice())
        .unwrap(),
      address
    );

    #[cfg(feature = "scale")]
    use scale::{Encode as _, DecodeAll as _};
    #[cfg(feature = "scale")]
    assert_eq!(
      ExternalAddress::decode_all(&mut borsh::to_vec(&address).unwrap().as_slice()).unwrap(),
      address
    );
    #[cfg(feature = "scale")]
    assert_eq!(
      ExternalAddress::deserialize_reader(&mut address.encode().as_slice()).unwrap(),
      address
    );
  }
}
