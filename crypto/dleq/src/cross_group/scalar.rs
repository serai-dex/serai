use ff::PrimeFieldBits;

use zeroize::Zeroize;

/// Convert a uniform scalar into one usable on both fields, clearing the top bits as needed.
pub fn scalar_normalize<F0: PrimeFieldBits + Zeroize, F1: PrimeFieldBits>(
  mut scalar: F0,
) -> (F0, F1) {
  let mutual_capacity = F0::CAPACITY.min(F1::CAPACITY);

  // The security of a mutual key is the security of the lower field. Accordingly, this bans a
  // difference of more than 4 bits
  #[cfg(feature = "secure_capacity_difference")]
  assert!((F0::CAPACITY.max(F1::CAPACITY) - mutual_capacity) < 4);

  let mut res1 = F0::zero();
  let mut res2 = F1::zero();
  // Uses the bit view API to ensure a consistent endianess
  let mut bits = scalar.to_le_bits();
  scalar.zeroize();
  // Convert it to big endian
  bits.reverse();

  let mut skip = bits.len() - usize::try_from(mutual_capacity).unwrap();
  // Needed to zero out the bits
  #[allow(unused_assignments)]
  for mut raw_bit in bits.iter_mut() {
    if skip > 0 {
      *raw_bit = false;
      skip -= 1;
      continue;
    }

    res1 = res1.double();
    res2 = res2.double();

    let mut bit = u8::from(*raw_bit);
    *raw_bit = false;

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

  let mut accum = F0::zero();
  for b in 0 .. capacity {
    accum = accum.double();
    accum += F0::from(((bytes[b / 8] >> (b % 8)) & 1).into());
  }
  (accum, scalar_convert(accum).unwrap())
}
