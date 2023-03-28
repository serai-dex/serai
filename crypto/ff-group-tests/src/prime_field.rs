use rand_core::RngCore;
use group::ff::{PrimeField, PrimeFieldBits};

use crate::field::test_field;

// Ideally, this and test_one would be under Field, yet these tests require access to From<u64>
/// Test zero returns F::from(0).
pub fn test_zero<F: PrimeField>() {
  assert_eq!(F::ZERO, F::from(0u64), "0 != 0");
}

/// Test one returns F::from(1).
pub fn test_one<F: PrimeField>() {
  assert_eq!(F::ONE, F::from(1u64), "1 != 1");
}

/// Test `From<u64>` for F works.
pub fn test_from_u64<F: PrimeField>() {
  assert_eq!(F::ONE, F::from(1u64), "1 != 1");
  assert_eq!(F::ONE.double(), F::from(2u64), "2 != 2");
  assert_eq!(F::ONE.double() + F::ONE, F::from(3u64), "3 != 3");
}

/// Test from_u128 for F works.
pub fn test_from_u128<F: PrimeField>() {
  assert_eq!(F::from(1u64), F::from_u128(1u128), "1u64 != 1u128");
  assert_eq!(F::from(2u64), F::from_u128(2u128), "2u64 != 2u128");
  assert_eq!(F::from(3u64), F::from_u128(3u128), "3u64 != 3u128");
}

/// Test is_odd/is_even works.
/// This test assumes an odd modulus with oddness being determined by the least-significant bit.
/// Accordingly, this test doesn't support fields alternatively defined.
/// TODO: Improve in the future.
pub fn test_is_odd<F: PrimeField>() {
  assert_eq!(F::ZERO.is_odd().unwrap_u8(), 0, "0 was odd");
  assert_eq!(F::ZERO.is_even().unwrap_u8(), 1, "0 wasn't even");

  assert_eq!(F::ONE.is_odd().unwrap_u8(), 1, "1 was even");
  assert_eq!(F::ONE.is_even().unwrap_u8(), 0, "1 wasn't odd");

  // Make sure an odd value added to an odd value is even
  let two = F::ONE.double();
  assert_eq!(two.is_odd().unwrap_u8(), 0, "2 was odd");
  assert_eq!(two.is_even().unwrap_u8(), 1, "2 wasn't even");

  // Make sure an even value added to an even value is even
  let four = two.double();
  assert_eq!(four.is_odd().unwrap_u8(), 0, "4 was odd");
  assert_eq!(four.is_even().unwrap_u8(), 1, "4 wasn't even");

  let neg_one = -F::ONE;
  assert_eq!(neg_one.is_odd().unwrap_u8(), 0, "-1 was odd");
  assert_eq!(neg_one.is_even().unwrap_u8(), 1, "-1 wasn't even");

  assert_eq!(neg_one.double().is_odd().unwrap_u8(), 1, "(-1).double() was even");
  assert_eq!(neg_one.double().is_even().unwrap_u8(), 0, "(-1).double() wasn't odd");
}

/// Test encoding and decoding of field elements.
pub fn test_encoding<F: PrimeField>() {
  let test = |scalar: F, msg| {
    let bytes = scalar.to_repr();
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(bytes.as_ref());
    assert_eq!(scalar, F::from_repr(repr).unwrap(), "{msg} couldn't be encoded and decoded");
    assert_eq!(
      scalar,
      F::from_repr_vartime(repr).unwrap(),
      "{msg} couldn't be encoded and decoded",
    );
    assert_eq!(
      bytes.as_ref(),
      F::from_repr(repr).unwrap().to_repr().as_ref(),
      "canonical encoding decoded produced distinct encoding"
    );
  };
  test(F::ZERO, "0");
  test(F::ONE, "1");
  test(F::ONE + F::ONE, "2");
  test(-F::ONE, "-1");

  // Also check if a non-canonical encoding is possible
  let mut high = (F::ZERO - F::ONE).to_repr();
  let mut possible_non_canon = false;
  for byte in high.as_mut() {
    // The fact a bit isn't set in the highest possible value suggests there's unused bits
    // If there's unused bits, mark the possibility of a non-canonical encoding and set the bits
    if *byte != 255 {
      possible_non_canon = true;
      *byte = 255;
      break;
    }
  }

  // Any non-canonical encoding should fail to be read
  if possible_non_canon {
    assert!(!bool::from(F::from_repr(high).is_some()));
  }
}

/// Run all tests on fields implementing PrimeField.
pub fn test_prime_field<R: RngCore, F: PrimeField>(rng: &mut R) {
  test_field::<R, F>(rng);

  test_zero::<F>();
  test_one::<F>();
  test_from_u64::<F>();
  test_from_u128::<F>();
  test_is_odd::<F>();

  // Do a sanity check on the CAPACITY. A full test can't be done at this time
  assert!(F::CAPACITY <= F::NUM_BITS, "capacity exceeded number of bits");

  test_encoding::<F>();
}

/// Test to_le_bits returns the little-endian bits of a value.
// This test assumes that the modulus is at least 4.
pub fn test_to_le_bits<F: PrimeField + PrimeFieldBits>() {
  {
    let bits = F::ZERO.to_le_bits();
    assert_eq!(bits.iter().filter(|bit| **bit).count(), 0, "0 had bits set");
  }

  {
    let bits = F::ONE.to_le_bits();
    assert!(bits[0], "1 didn't have its least significant bit set");
    assert_eq!(bits.iter().filter(|bit| **bit).count(), 1, "1 had multiple bits set");
  }

  {
    let bits = F::from(2).to_le_bits();
    assert!(bits[1], "2 didn't have its second bit set");
    assert_eq!(bits.iter().filter(|bit| **bit).count(), 1, "2 had multiple bits set");
  }

  {
    let bits = F::from(3).to_le_bits();
    assert!(bits[0], "3 didn't have its first bit set");
    assert!(bits[1], "3 didn't have its second bit set");
    assert_eq!(bits.iter().filter(|bit| **bit).count(), 2, "2 didn't have two bits set");
  }
}

/// Test char_le_bits returns the bits of the modulus.
pub fn test_char_le_bits<F: PrimeField + PrimeFieldBits>() {
  // A field with a modulus of 0 may be technically valid? Yet these tests assume some basic
  // functioning.
  assert!(F::char_le_bits().iter().any(|bit| *bit), "char_le_bits contained 0");

  // Test this is the bit pattern of the modulus by reconstructing the modulus from it
  let mut bit = F::ONE;
  let mut modulus = F::ZERO;
  for set in F::char_le_bits() {
    if set {
      modulus += bit;
    }
    bit = bit.double();
  }
  assert_eq!(modulus, F::ZERO, "char_le_bits did not contain the field's modulus");
}

/// Test NUM_BITS is accurate.
pub fn test_num_bits<F: PrimeField + PrimeFieldBits>() {
  let mut val = F::ONE;
  let mut bit = 0;
  while ((bit + 1) < val.to_le_bits().len()) && val.double().to_le_bits()[bit + 1] {
    val = val.double();
    bit += 1;
  }
  assert_eq!(
    F::NUM_BITS,
    u32::try_from(bit + 1).unwrap(),
    "NUM_BITS was incorrect. it should be {}",
    bit + 1
  );
}

/// Test CAPACITY is accurate.
pub fn test_capacity<F: PrimeField + PrimeFieldBits>() {
  assert!(F::CAPACITY <= F::NUM_BITS, "capacity exceeded number of bits");

  let mut val = F::ONE;
  assert!(val.to_le_bits()[0], "1 didn't have its least significant bit set");
  for b in 1 .. F::CAPACITY {
    val = val.double();
    val += F::ONE;
    for i in 0 ..= b {
      assert!(
        val.to_le_bits()[usize::try_from(i).unwrap()],
        "couldn't set a bit within the capacity",
      );
    }
  }

  // If the field has a modulus which is a power of 2, NUM_BITS should equal CAPACITY
  // Adding one would also be sufficient to trigger an overflow
  if F::char_le_bits().iter().filter(|bit| **bit).count() == 1 {
    assert_eq!(
      F::NUM_BITS,
      F::CAPACITY,
      "field has a power of two modulus yet CAPACITY doesn't equal NUM_BITS",
    );
    assert_eq!(val + F::ONE, F::ZERO);
    return;
  }

  assert_eq!(F::NUM_BITS - 1, F::CAPACITY, "capacity wasn't NUM_BITS - 1");
}

fn pow<F: PrimeFieldBits>(base: F, exp: F) -> F {
  let mut res = F::ONE;
  for bit in exp.to_le_bits().iter().rev() {
    res *= res;
    if *bit {
      res *= base;
    }
  }
  res
}

// Ideally, this would be under field.rs, yet the above pow function requires PrimeFieldBits
/// Perform basic tests on the pow functions, even when passed non-canonical inputs.
pub fn test_pow<F: PrimeFieldBits>() {
  // Sanity check the local pow algorithm. Does not have assert messages as these shouldn't fail
  assert_eq!(pow(F::ONE, F::ZERO), F::ONE);
  assert_eq!(pow(F::ONE.double(), F::ZERO), F::ONE);
  assert_eq!(pow(F::ONE, F::ONE), F::ONE);

  let two = F::ONE.double();
  assert_eq!(pow(two, F::ONE), two);
  assert_eq!(pow(two, two), two.double());
  let three = two + F::ONE;
  assert_eq!(pow(three, F::ONE), three);
  assert_eq!(pow(three, two), three * three);
  assert_eq!(pow(three, three), three * three * three);

  // Choose a small base without a notably uniform bit pattern
  let bit_0 = F::ONE;
  let base = {
    let bit_1 = bit_0.double();
    let bit_2 = bit_1.double();
    let bit_3 = bit_2.double();
    let bit_4 = bit_3.double();
    let bit_5 = bit_4.double();
    let bit_6 = bit_5.double();
    let bit_7 = bit_6.double();
    bit_7 + bit_6 + bit_5 + bit_2 + bit_0
  };

  // Ensure pow/pow_vartime return 1 when the base is raised to 0, handling malleated inputs
  assert_eq!(base.pow([]), F::ONE, "pow x^0 ([]) != 1");
  assert_eq!(base.pow_vartime([]), F::ONE, "pow x^0 ([]) != 1");
  assert_eq!(base.pow([0]), F::ONE, "pow_vartime x^0 ([0]) != 1");
  assert_eq!(base.pow_vartime([0]), F::ONE, "pow_vartime x^0 ([0]) != 1");
  assert_eq!(base.pow([0, 0]), F::ONE, "pow x^0 ([0, 0]) != 1");
  assert_eq!(base.pow_vartime([0, 0]), F::ONE, "pow_vartime x^0 ([0, 0]) != 1");

  // Ensure pow/pow_vartime return the base when raised to 1, handling malleated inputs
  assert_eq!(base.pow([1]), base, "pow x^1 ([1]) != x");
  assert_eq!(base.pow_vartime([1, 0]), base, "pow_vartime x^1 ([1, 0]) != x");
  assert_eq!(base.pow([1]), base, "pow x^1 ([1]) != x");
  assert_eq!(base.pow_vartime([1, 0]), base, "pow_vartime x^1 ([1, 0]) != x");

  // Ensure pow/pow_vartime can handle multiple u64s properly
  // Create a scalar which exceeds u64
  let mut bit_64 = bit_0;
  for _ in 0 .. 64 {
    bit_64 = bit_64.double();
  }
  // Run the tests
  assert_eq!(base.pow([0, 1]), pow(base, bit_64), "pow x^(2^64) != x^(2^64)");
  assert_eq!(base.pow_vartime([0, 1]), pow(base, bit_64), "pow_vartime x^(2^64) != x^(2^64)");
  assert_eq!(base.pow([1, 1]), pow(base, bit_64 + F::ONE), "pow x^(2^64 + 1) != x^(2^64 + 1)");
  assert_eq!(
    base.pow_vartime([1, 1]),
    pow(base, bit_64 + F::ONE),
    "pow_vartime x^(2^64 + 1) != x^(2^64 + 1)"
  );
}

/// Test the inverted constants are correct.
pub fn test_inv_consts<F: PrimeFieldBits>() {
  assert_eq!(F::TWO_INV, F::from(2u64).invert().unwrap());
  assert_eq!(F::ROOT_OF_UNITY_INV, F::ROOT_OF_UNITY.invert().unwrap());
}

/// Test S is correct.
pub fn test_s<F: PrimeFieldBits>() {
  // "This is the number of leading zero bits in the little-endian bit representation of
  // `modulus - 1`."
  let mut s = 0;
  for b in (F::ZERO - F::ONE).to_le_bits() {
    if b {
      break;
    }
    s += 1;
  }
  assert_eq!(s, F::S, "incorrect S");
}

/// Test the root of unity is correct for the provided multiplicative generator.
pub fn test_root_of_unity<F: PrimeFieldBits>() {
  // "It can be calculated by exponentiating `Self::multiplicative_generator` by `t`, where
  // `t = (modulus - 1) >> Self::S`."

  // Get the bytes to shift
  let mut bits = (F::ZERO - F::ONE).to_le_bits().iter().map(|bit| *bit).collect::<Vec<_>>();
  for _ in 0 .. F::S {
    bits.remove(0);
  }

  // Construct t
  let mut bit = F::ONE;
  let mut t = F::ZERO;
  for set in bits {
    if set {
      t += bit;
    }
    bit = bit.double();
  }
  assert!(bool::from(t.is_odd()), "t wasn't odd");

  assert_eq!(pow(F::MULTIPLICATIVE_GENERATOR, t), F::ROOT_OF_UNITY, "incorrect root of unity");
  assert_eq!(
    pow(F::ROOT_OF_UNITY, pow(F::from(2u64), F::from(F::S.into()))),
    F::ONE,
    "root of unity raised to 2^S wasn't 1"
  );
}

/// Test DELTA is correct.
pub fn test_delta<F: PrimeFieldBits>() {
  assert_eq!(
    pow(F::MULTIPLICATIVE_GENERATOR, pow(F::from(2u64), F::from(u64::from(F::S)))),
    F::DELTA,
  );
}

/// Run all tests on fields implementing PrimeFieldBits.
pub fn test_prime_field_bits<R: RngCore, F: PrimeFieldBits>(rng: &mut R) {
  test_prime_field::<R, F>(rng);

  test_to_le_bits::<F>();
  test_char_le_bits::<F>();

  test_pow::<F>();

  test_inv_consts::<F>();
  test_s::<F>();
  test_root_of_unity::<F>();
  test_delta::<F>();

  test_num_bits::<F>();
  test_capacity::<F>();
}
