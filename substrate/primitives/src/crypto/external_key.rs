use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

/// A key for an external network.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExternalKey(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  pub BoundedVec<u8, ConstU32<{ ExternalKey::MAX_LEN }>>,
);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalKey);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for ExternalKey {
  fn max_encoded_len() -> usize {
    crate::borsh_max_encoded_len_bounded_vec::<{ ExternalKey::MAX_LEN }, u8>()
  }
}

impl AsRef<[u8]> for ExternalKey {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl Zeroize for ExternalKey {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize();
  }
}

impl ExternalKey {
  /// The maximum length for an external key.
  /*
    This support keys up to 96 bytes (such as BLS12-381 G2, which is the largest elliptic-curve
    group element we might reasonably use as a key). This can always be increased if we need to
    adopt a different cryptosystem (one where verification keys are multiple group elements, or
    where group elements do exceed 96 bytes, such as RSA).
  */
  pub const MAX_LEN: u32 = 96;
}

#[test]
fn external_key() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  #[cfg(feature = "scale")]
  use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};

  // Check `max_encoded_len` is correctly defined
  #[cfg(feature = "scale")]
  assert_eq!(
    ExternalKey::max_encoded_len(),
    ExternalKey({
      let mut vec = BoundedVec::new();
      while vec.try_push(0).is_ok() {}
      vec
    })
    .encode()
    .len()
  );

  // Fuzz test various `ExternalKey`s
  for i in 0 ..= ExternalKey::MAX_LEN {
    let mut vec = vec![0; usize::try_from(i).unwrap()];
    OsRng.fill_bytes(&mut vec);
    let external_key = ExternalKey(vec.try_into().unwrap());

    assert_eq!(
      ExternalKey::deserialize_reader(&mut borsh::to_vec(&external_key).unwrap().as_slice())
        .unwrap(),
      external_key
    );

    #[cfg(feature = "scale")]
    assert_eq!(
      ExternalKey::decode_all(&mut borsh::to_vec(&external_key).unwrap().as_slice()).unwrap(),
      external_key
    );
    #[cfg(feature = "scale")]
    assert_eq!(
      ExternalKey::deserialize_reader(&mut external_key.encode().as_slice()).unwrap(),
      external_key
    );
  }
}
