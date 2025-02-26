use borsh::{io::*, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

pub fn borsh_serialize_bitvec<W: Write>(
  bitvec: &bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
  writer: &mut W,
) -> Result<()> {
  let vec: &[u8] = bitvec.as_raw_slice();
  BorshSerialize::serialize(vec, writer)
}

pub fn borsh_deserialize_bitvec<R: Read>(
  reader: &mut R,
) -> Result<bitvec::vec::BitVec<u8, bitvec::order::Lsb0>> {
  let bitvec: alloc::vec::Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
  Ok(bitvec::vec::BitVec::from_vec(bitvec))
}

type SerializeBoundedVecAs<T> = alloc::vec::Vec<T>;

// TODO: Don't serialize this as a Vec<u8>. Shorten the length-prefix, technically encoding as an
// enum.
pub fn borsh_serialize_bounded_vec<W: Write, T: BorshSerialize, const B: u32>(
  bounded: &BoundedVec<T, ConstU32<B>>,
  writer: &mut W,
) -> Result<()> {
  let vec: &SerializeBoundedVecAs<T> = bounded.as_ref();
  BorshSerialize::serialize(vec, writer)
}

pub fn borsh_deserialize_bounded_vec<R: Read, T: BorshDeserialize, const B: u32>(
  reader: &mut R,
) -> Result<BoundedVec<T, ConstU32<B>>> {
  let vec: SerializeBoundedVecAs<T> = BorshDeserialize::deserialize_reader(reader)?;
  vec.try_into().map_err(|_| Error::new(ErrorKind::Other, "bound exceeded"))
}
