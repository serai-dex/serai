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

pub fn borsh_serialize_bounded_vec<W: Write, T: BorshSerialize, const B: u32>(
  bounded: &BoundedVec<T, ConstU32<B>>,
  writer: &mut W,
) -> Result<()> {
  // Won't panic as `bytes_for_length` is <= 4
  let bytes_for_length =
    usize::try_from((u32::BITS - B.leading_zeros()).div_ceil(u8::BITS)).unwrap();
  // Won't panic as this vec is bounded to a length specified as a u32
  let length = u32::try_from(bounded.len()).unwrap().to_le_bytes();
  writer.write_all(&length[0 .. bytes_for_length])?;

  for item in bounded.as_slice() {
    BorshSerialize::serialize(item, writer)?;
  }

  Ok(())
}

pub fn borsh_deserialize_bounded_vec<R: Read, T: BorshDeserialize, const B: u32>(
  reader: &mut R,
) -> Result<BoundedVec<T, ConstU32<B>>> {
  // Won't panic as `bytes_for_length` is <= 4
  let bytes_for_length =
    usize::try_from((u32::BITS - B.leading_zeros()).div_ceil(u8::BITS)).unwrap();
  let mut length = [0u8; 4];
  reader.read_exact(&mut length[.. bytes_for_length])?;
  let length = u32::from_le_bytes(length);
  if length > B {
    #[allow(clippy::io_other_error)]
    Err(Error::new(ErrorKind::Other, "bound exceeded"))?;
  }

  // Won't panic so long as usize >= u32
  const {
    assert!(usize::BITS >= u32::BITS, "wasn't compiled for at least a 32-bit platform");
  }
  let mut vec = alloc::vec::Vec::with_capacity(length.try_into().unwrap());
  for _ in 0 .. length {
    vec.push(T::deserialize_reader(reader)?);
  }
  // Won't panic as we already checked against the bound
  Ok(vec.try_into().map_err(|_| ()).unwrap())
}
