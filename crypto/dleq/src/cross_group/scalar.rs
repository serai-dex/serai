use ff::PrimeFieldBits;

/// Convert a uniform scalar into one usable on both fields, clearing the top bits as needed
pub fn scalar_normalize<F0: PrimeFieldBits, F1: PrimeFieldBits>(scalar: F0) -> (F0, F1) {
  let mutual_capacity = F0::CAPACITY.min(F1::CAPACITY);

  // The security of a mutual key is the security of the lower field. Accordingly, this bans a
  // difference of more than 4 bits
  #[cfg(feature = "secure_capacity_difference")]
  assert!((F0::CAPACITY.max(F1::CAPACITY) - mutual_capacity) < 4);

  let mut res1 = F0::zero();
  let mut res2 = F1::zero();
  // Uses the bit view API to ensure a consistent endianess
  let mut bits = scalar.to_le_bits();
  // Convert it to big endian
  bits.reverse();
  for bit in bits.iter().skip(bits.len() - usize::try_from(mutual_capacity).unwrap()) {
    res1 = res1.double();
    res2 = res2.double();
    if *bit {
      res1 += F0::one();
      res2 += F1::one();
    }
  }

  (res1, res2)
}

/// Helper to convert a scalar between fields. Returns None if the scalar isn't mutually valid
pub fn scalar_convert<F0: PrimeFieldBits, F1: PrimeFieldBits>(scalar: F0) -> Option<F1> {
  let (valid, converted) = scalar_normalize(scalar);
  Some(converted).filter(|_| scalar == valid)
}
