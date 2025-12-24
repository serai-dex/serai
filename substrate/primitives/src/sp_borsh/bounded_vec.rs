//! (De)serialization of [`BoundedVec`].
//!
//! While we have to implement the [`borsh`] API for [`BoundedVec`], we also re-define the length
//! prefix to be the one defined within the Serai protocol.

use borsh::{io::*, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

/// Calculate the maximum length of a [`BoundedVec`] when serialized.
///
/// This may panic on overflow.
#[cfg(feature = "scale")]
pub fn borsh_max_encoded_len_bounded_vec<const BOUND: u32, T: scale::MaxEncodedLen>() -> usize {
  // The maximum length is the length of the length prefix plus the maximum length of the value
  let length_prefix_len = usize::from(super::length_prefix::len(u64::from(BOUND)));
  let max_values_len = {
    let bound = usize::try_from(BOUND).expect("bound did not fit within the platform's `usize`");
    bound * T::max_encoded_len()
  };
  length_prefix_len + max_values_len
}

/// Serialize a [`BoundedVec`] with a `borsh`-compatible API.
///
/// While a `borsh`-compatible API, this is not compatible with the Borsh specification.
pub fn borsh_serialize_bounded_vec<W: Write, T: BorshSerialize, const BOUND: u32>(
  bounded: &BoundedVec<T, ConstU32<BOUND>>,
  writer: &mut W,
) -> Result<()> {
  // This won't panic as this container is bounded to a length specified as a `u64`
  let length = u64::try_from(bounded.len()).unwrap();
  super::length_prefix::write(u64::from(BOUND), writer, length)?;

  for item in bounded.as_slice() {
    BorshSerialize::serialize(item, writer)?;
  }

  Ok(())
}

/// Deerialize a [`BoundedVec`] with a `borsh`-compatible API.
///
/// While a `borsh`-compatible API, this is not compatible with the Borsh specification.
pub fn borsh_deserialize_bounded_vec<R: Read, T: BorshDeserialize, const BOUND: u32>(
  reader: &mut R,
) -> Result<BoundedVec<T, ConstU32<BOUND>>> {
  let length = super::length_prefix::read(u64::from(BOUND), reader)?;
  let mut vec = alloc::vec::Vec::new();
  for _ in 0 .. length {
    vec.push(T::deserialize_reader(reader)?);
  }
  // This won't panic as we already checked the length fits within the bound
  Ok(vec.try_into().map_err(|_| ()).unwrap())
}

#[test]
#[expect(clippy::as_conversions, clippy::cast_lossless)]
fn max_encoded_len() {
  macro_rules! test_case {
    ($length_prefix_len: literal, $bound: expr) => {
      // Unit types should always have a length equivalent to the length of the length prefix
      assert_eq!(borsh_max_encoded_len_bounded_vec::<{ $bound }, ()>(), $length_prefix_len);
      // Now we test with `u8` and `u16`
      assert_eq!(
        borsh_max_encoded_len_bounded_vec::<{ $bound }, u8>(),
        $length_prefix_len + usize::try_from($bound * (u8::BITS / 8)).unwrap()
      );
      assert_eq!(
        borsh_max_encoded_len_bounded_vec::<{ $bound }, u16>(),
        $length_prefix_len + usize::try_from($bound * (u16::BITS / 8)).unwrap()
      );
    };
  }
  test_case!(0, 0);
  test_case!(1, u8::MAX as u32);
  test_case!(2, u16::MAX as u32);
  test_case!(4, u32::MAX / 8);
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};

  // Test writing a vector with a bound of 0
  {
    let bounded = BoundedVec::<u64, ConstU32<0>>::new();
    let mut encoding = vec![];
    borsh_serialize_bounded_vec(&bounded, &mut encoding).unwrap();
    assert!(encoding.is_empty());
    assert_eq!(
      bounded,
      borsh_deserialize_bounded_vec::<_, _, 0>(&mut encoding.as_slice()).unwrap()
    );
  }

  // Test writing a vector whose bound is expressible as a `u8`
  {
    const BOUND: u32 = 1;
    let value = OsRng.next_u64();
    let bounded = BoundedVec::<u64, ConstU32<BOUND>>::try_from(vec![value]).unwrap();
    let mut encoding = vec![];
    borsh_serialize_bounded_vec(&bounded, &mut encoding).unwrap();
    assert_eq!(encoding, [[1].as_slice(), value.to_le_bytes().as_slice()].concat());
    assert_eq!(
      bounded,
      borsh_deserialize_bounded_vec::<_, _, BOUND>(&mut encoding.as_slice()).unwrap()
    );
  }

  // Test writing a vector whose bound is expressible as a `u16`
  {
    const BOUND: u32 = 256;
    let value = OsRng.next_u64();
    let bounded = BoundedVec::<u64, ConstU32<BOUND>>::try_from(vec![value]).unwrap();
    let mut encoding = vec![];
    borsh_serialize_bounded_vec(&bounded, &mut encoding).unwrap();
    assert_eq!(encoding, [[1, 0].as_slice(), value.to_le_bytes().as_slice()].concat());
    assert_eq!(
      bounded,
      borsh_deserialize_bounded_vec::<_, _, BOUND>(&mut encoding.as_slice()).unwrap()
    );
  }

  // Deserialization of a `BitVec` whose length exceeds the bound
  borsh_deserialize_bounded_vec::<_, u8, 1>(&mut [2, 1, 1].as_slice()).unwrap_err();

  // Fuzz test various `BoundedVec`s
  macro_rules! test_case {
    ($bound: literal, $value: ty) => {
      for _ in 0 .. 100 {
        let mut vec = vec![0; usize::try_from(OsRng.next_u64() % $bound).unwrap()];
        #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
        for item in vec.iter_mut() {
          *item = OsRng.next_u64() as $value;
        }
        let bounded = BoundedVec::<$value, ConstU32<{ $bound }>>::try_from(vec)
          .expect("`Vec` whose length was less than bound couldn't convert into `BoundedVec`");
        let mut encoding = vec![];
        borsh_serialize_bounded_vec(&bounded, &mut encoding).unwrap();
        assert_eq!(
          bounded,
          borsh_deserialize_bounded_vec::<_, _, $bound>(&mut encoding.as_slice()).unwrap()
        );
      }
    };
  }
  test_case!(255, u8);
  test_case!(255, u16);
  test_case!(65535, u8);
  test_case!(65535, u16);
}
