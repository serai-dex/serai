//! (De)serialization of [`BitVec`].
//!
//! Borsh does not define in its specification an optimized encoding for a vector of bits. We
//! define the (de)serialization of a vector of bits as the amount of bits followed by the packed
//! `[u8]` encoding of this bits, where the lowest bit in the first byte is the first bit of the
//! vector, continuing from there.
//!
//! To encode the amount of bits, we use the length-prefixing scheme defined within the Serai
//! protocol.

use core::ops::Deref;
use alloc::vec::Vec;

use borsh::{
  io::{Read, Write, Error},
  BorshSerialize, BorshDeserialize,
};

type BitVecInner = bitvec::vec::BitVec<u8, bitvec::order::Lsb0>;
/// A vector of bits, defined as needed by the Serai protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitVec<const BOUND: u64>(BitVecInner);

impl<const BOUND: u64> Deref for BitVec<BOUND> {
  type Target = BitVecInner;
  fn deref(&self) -> &BitVecInner {
    &self.0
  }
}
impl<'vec, const BOUND: u64> IntoIterator for &'vec BitVec<BOUND> {
  type Item = <&'vec BitVecInner as IntoIterator>::Item;
  type IntoIter = <&'vec BitVecInner as IntoIterator>::IntoIter;
  fn into_iter(self) -> Self::IntoIter {
    self.0.iter()
  }
}
impl<const BOUND: u64> TryFrom<BitVecInner> for BitVec<BOUND> {
  type Error = ();
  fn try_from(bitvec: BitVecInner) -> Result<Self, ()> {
    if u64::try_from(bitvec.len()).map_err(|_| ())? > BOUND {
      Err(())?;
    }
    Ok(Self(bitvec))
  }
}

impl<const BOUND: u64> BorshSerialize for BitVec<BOUND> {
  fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
    // This won't panic as this container is bounded to a length specified as a `u64`
    let length = u64::try_from(self.0.len()).unwrap();
    super::length_prefix::write(BOUND, writer, length)?;

    // The `BitVec` leaves unused bits arbitrarily defined, so we normalize the encoded memory here
    let mut vec = self.0.clone();
    vec.set_uninitialized(false);
    writer.write_all(vec.as_raw_slice())
  }
}

impl<const BOUND: u64> BorshDeserialize for BitVec<BOUND> {
  fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
    let bits = super::length_prefix::read(BOUND, reader)?;

    const LENGTH_ERROR: &str = "length of `BitVec` did not fit within platform's `usize`";
    let bits = usize::try_from(bits).map_err(|_| Error::other(LENGTH_ERROR))?;

    let mut result = Vec::new();
    {
      let mut bytes = bits.div_ceil(8);
      /*
        Due to the risk this encoding is short, we do not allocate the entire vector up front.
        Instead, we reserve a chunk large enough to be efficient and small enough to not be a DoS
        concern, reading chunk by chunk, bounding the worst-case asymmetry between
        bytes sent/memory allocated to a single instance of the chunk size.
      */
      let mut chunk = [0; 128];
      while bytes > 0 {
        let chunk = {
          let this_chunk_len = chunk.len().min(bytes);
          &mut chunk[.. this_chunk_len]
        };
        reader.read_exact(chunk)?;
        result.extend(&*chunk);
        bytes -= chunk.len();
      }
    }

    // This result will have as many bits as could possibly fit in this `Vec`
    // We only expect, and only want, `bits` bits however
    let mut result = BitVecInner::try_from_vec(result).map_err(|_| Error::other(LENGTH_ERROR))?;
    // We first check the unused bits aren't set to ensure this was canonically encoded
    if result.as_bitslice().iter().skip(bits).any(|bit| *bit) {
      Err(Error::other("non-canonical bit vector due to unused bits being set"))?;
    }
    // We then call truncate so we only have the bits we expect to have
    result.truncate(bits);
    Ok(Self(result))
  }
}

#[cfg(feature = "scale")]
crate::borsh_as_scale!(BOUND u64, BitVec);

#[test]
fn try_from() {
  use bitvec::{order::Lsb0, bitvec};

  {
    let empty = BitVec::<1>::try_from(bitvec!(u8, Lsb0; 0; 0)).unwrap();
    assert_eq!(empty.len(), 0);
  }

  {
    let at_bound = BitVec::<1>::try_from(bitvec!(u8, Lsb0; 0; 1)).unwrap();
    assert_eq!(at_bound.len(), 1);
  }

  // Converting a `BitVec` whose length exceeds the bound should fail
  BitVec::<1>::try_from(bitvec!(u8, Lsb0; 0; 2)).unwrap_err();
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};
  use bitvec::{order::Lsb0, bitvec};

  macro_rules! explicit_test {
    ($bound: literal, $value: expr, $expected_encoding: expr) => {
      let value = BitVec::<$bound>::try_from($value).unwrap();
      let encoding = borsh::to_vec(&value).unwrap();
      assert_eq!(encoding, $expected_encoding, "encoding wasn't as expected");
      assert_eq!(
        BitVec::<$bound>::deserialize_reader(&mut encoding.as_slice()).unwrap(),
        value,
        "deserialization wasn't as expected"
      );
    };
  }

  // Serialization of a `BitVec` bounded to 0
  explicit_test!(0, bitvec!(u8, Lsb0; 0; 0), vec![]);
  // Serialization of a `BitVec` with a single bit, whose length is bounded to a single byte
  explicit_test!(1, bitvec!(u8, Lsb0; 1; 1), vec![1, 1]);
  // Serialization of a `BitVec` with a single bit, whose length is bounded to two bytes
  explicit_test!(256, bitvec!(u8, Lsb0; 1; 1), vec![1, 0, 1]);
  // Serialization of a `BitVec` with two bits
  explicit_test!(2, bitvec!(u8, Lsb0; 0, 0), vec![2, 0b00]);
  explicit_test!(2, bitvec!(u8, Lsb0; 0, 1), vec![2, 0b10]);
  explicit_test!(2, bitvec!(u8, Lsb0; 1, 0), vec![2, 0b01]);
  explicit_test!(2, bitvec!(u8, Lsb0; 1, 1), vec![2, 0b11]);
  // Deserialization of a `BitVec` whose length exceeds the bound
  BitVec::<1>::deserialize_reader(&mut [2, 1].as_slice()).unwrap_err();
  // Deserialization of a non-canonically-encoded `BitVec`
  BitVec::<1>::deserialize_reader(&mut [1, 0xff].as_slice()).unwrap_err();

  // Fuzz test various `BitVec`s
  macro_rules! test_case {
    ($bound: literal) => {
      for _ in 0 .. 100 {
        let len = usize::try_from(OsRng.next_u64() % $bound).unwrap();
        let mut vec = bitvec::vec::BitVec::new();
        for _ in 0 .. len {
          vec.push((OsRng.next_u64() & 1) == 1);
        }
        let vec = BitVec::<$bound>::try_from(vec)
          .expect("`Vec` whose length was less than bound couldn't convert into `BitVec`");
        assert_eq!(
          BitVec::<$bound>::deserialize_reader(&mut borsh::to_vec(&vec).unwrap().as_slice())
            .unwrap(),
          vec
        );

        #[cfg(feature = "scale")]
        use scale::{Encode, DecodeAll};
        #[cfg(feature = "scale")]
        assert_eq!(
          BitVec::<$bound>::decode_all(&mut borsh::to_vec(&vec).unwrap().as_slice()).unwrap(),
          vec
        );
        #[cfg(feature = "scale")]
        assert_eq!(
          BitVec::<$bound>::deserialize_reader(&mut vec.encode().as_slice()).unwrap(),
          vec
        );
      }
    };
  }
  test_case!(255);
  test_case!(65535);
}
