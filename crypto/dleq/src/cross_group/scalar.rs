use core::ops::DerefMut;

use ff::PrimeFieldBits;

use zeroize::Zeroize;

use crate::cross_group::u8_from_bool;

/// Convert a uniform scalar into one usable on both fields, clearing the top bits as needed.
pub fn scalar_normalize<F0: PrimeFieldBits + Zeroize, F1: PrimeFieldBits>(
  mut scalar: F0,
) -> (F0, F1) {
  let mutual_capacity = F0::CAPACITY.min(F1::CAPACITY);

  // A mutual key is only as secure as its weakest group
  // Accordingly, this bans a capacity difference of more than 4 bits to prevent a curve generally
  // offering n-bits of security from being forced into a situation with much fewer bits
  #[cfg(feature = "secure_capacity_difference")]
  assert!((F0::CAPACITY.max(F1::CAPACITY) - mutual_capacity) <= 4);

  let mut res1 = F0::ZERO;
  let mut res2 = F1::ZERO;
  // Uses the bits API to ensure a consistent endianess
  let mut bits = scalar.to_le_bits();
  scalar.zeroize();
  // Convert it to big endian
  bits.reverse();

  let mut skip = bits.len() - usize::try_from(mutual_capacity).unwrap();
  // Needed to zero out the bits
  #[allow(unused_assignments)]
  for mut bit in &mut bits {
    if skip > 0 {
      bit.deref_mut().zeroize();
      skip -= 1;
      continue;
    }

    res1 = res1.double();
    res2 = res2.double();

    let mut bit = u8_from_bool(bit.deref_mut());
    res1 += F0::from(bit.into());
    res2 += F1::from(bit.into());
    bit.zeroize();
  }

  (res1, res2)
}

/// Helper to convert a scalar between fields. Returns None if the scalar isn't mutually valid.
pub fn scalar_convert<F0: PrimeFieldBits + Zeroize, F1: PrimeFieldBits>(
  mut scalar: F0,
) -> Option<F1> {
  let (mut valid, converted) = scalar_normalize(scalar);
  let res = Some(converted).filter(|_| scalar == valid);
  scalar.zeroize();
  valid.zeroize();
  res
}

/// Create a mutually valid scalar from bytes via bit truncation to not introduce bias.
pub fn mutual_scalar_from_bytes<F0: PrimeFieldBits + Zeroize, F1: PrimeFieldBits>(
  bytes: &[u8],
) -> (F0, F1) {
  let capacity = usize::try_from(F0::CAPACITY.min(F1::CAPACITY)).unwrap();
  debug_assert!((bytes.len() * 8) >= capacity);

  let mut accum = F0::ZERO;
  for b in 0 .. capacity {
    accum = accum.double();
    accum += F0::from(((bytes[b / 8] >> (b % 8)) & 1).into());
  }
  (accum, scalar_convert(accum).unwrap())
}
