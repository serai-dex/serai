use num_bigint::BigUint;

pub fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
  let modulus = BigUint::from_bytes_be(modulus);
  // `aurora-engine-modexp` returns `vec![]` for this edge case
  if modulus == BigUint::ZERO {
    return vec![];
  }
  let base = BigUint::from_bytes_be(base);
  let exponent = BigUint::from_bytes_be(exponent);
  base.modpow(&exponent, &modulus).to_bytes_be()
}
