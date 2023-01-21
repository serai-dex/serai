use group::ff::Field;

/// Perform basic tests on equality.
pub fn test_eq<F: Field>() {
  let zero = F::zero();
  let one = F::one();

  assert!(zero != one, "0 == 1");
  assert!(!bool::from(zero.ct_eq(&one)), "0 ct_eq 1");

  assert_eq!(zero, F::zero(), "0 != 0");
  assert!(bool::from(zero.ct_eq(&F::zero())), "0 !ct_eq 0");

  assert_eq!(one, F::one(), "1 != 1");
  assert!(bool::from(one.ct_eq(&F::one())), "1 !ct_eq 1");
}

/// Verify conditional selection works. Doesn't verify it's actually constant time.
pub fn test_conditional_select<F: Field>() {
  let zero = F::zero();
  let one = F::one();
  assert_eq!(F::conditional_select(&zero, &one, 0.into()), zero, "couldn't select when false");
  assert_eq!(F::conditional_select(&zero, &one, 1.into()), one, "couldn't select when true");
}

/// Perform basic tests on addition.
pub fn test_add<F: Field>() {
  assert_eq!(F::zero() + F::zero(), F::zero(), "0 + 0 != 0");
  assert_eq!(F::zero() + F::one(), F::one(), "0 + 1 != 1");
  assert_eq!(F::one() + F::zero(), F::one(), "1 + 0 != 1");
  // Only PrimeField offers From<u64>
  // Accordingly, we assume either double or addition is correct
  // They either have to be matchingly correct or matchingly incorrect, yet we can't
  // reliably determine that here
  assert_eq!(F::one() + F::one(), F::one().double(), "1 + 1 != 2");
}

/// Perform basic tests on subtraction.
pub fn test_sub<F: Field>() {
  assert_eq!(F::zero() - F::zero(), F::zero(), "0 - 0 != 0");
  assert_eq!(F::one() - F::zero(), F::one(), "1 - 0 != 1");
  assert_eq!(F::one() - F::one(), F::zero(), "1 - 1 != 0");
}

/// Perform basic tests on negation.
pub fn test_neg<F: Field>() {
  assert_eq!(-F::zero(), F::zero(), "-0 != 0");
  assert_eq!(-(-F::one()), F::one(), "-(-1) != 1");
  assert_eq!(F::one() + (-F::one()), F::zero(), "1 + -1 != 0");
  assert_eq!(F::one() - (-F::one()), F::one().double(), "1 - -1 != 2");
}

/// Perform basic tests on multiplication.
pub fn test_mul<F: Field>() {
  assert_eq!(F::zero() * F::zero(), F::zero(), "0 * 0 != 0");
  assert_eq!(F::one() * F::zero(), F::zero(), "1 * 0 != 0");
  assert_eq!(F::one() * F::one(), F::one(), "1 * 1 != 1");
  let two = F::one().double();
  assert_eq!(two * (two + F::one()), two + two + two, "2 * 3 != 6");
}

/// Perform basic tests on the square function.
pub fn test_square<F: Field>() {
  assert_eq!(F::zero().square(), F::zero(), "0^2 != 0");
  assert_eq!(F::one().square(), F::one(), "1^2 != 1");
  let two = F::one().double();
  assert_eq!(two.square(), two + two, "2^2 != 4");
  let three = two + F::one();
  assert_eq!(three.square(), three * three, "3^2 != 9");
}

/// Perform basic tests on the invert function.
pub fn test_invert<F: Field>() {
  assert!(bool::from(F::zero().invert().is_none()), "0.invert() is some");
  assert_eq!(F::one().invert().unwrap(), F::one(), "1.invert() != 1");

  let two = F::one().double();
  let three = two + F::one();
  assert_eq!(two * three.invert().unwrap() * three, two, "2 * 3.invert() * 3 != 2");
}

/// Perform basic tests on the sqrt function.
pub fn test_sqrt<F: Field>() {
  assert_eq!(F::zero().sqrt().unwrap(), F::zero(), "sqrt(0) != 0");
  assert_eq!(F::one().sqrt().unwrap(), F::one(), "sqrt(1) != 1");

  let mut has_root = F::one().double();
  while bool::from(has_root.sqrt().is_none()) {
    has_root += F::one();
  }
  let root = has_root.sqrt().unwrap();
  assert_eq!(root * root, has_root, "sqrt(x)^2 != x");
}

/// Perform basic tests on the is_zero functions.
pub fn test_is_zero<F: Field>() {
  assert!(bool::from(F::zero().is_zero()), "0 is not 0");
  assert!(F::zero().is_zero_vartime(), "0 is not 0");
}

/// Perform basic tests on the cube function.
pub fn test_cube<F: Field>() {
  assert_eq!(F::zero().cube(), F::zero(), "0^3 != 0");
  assert_eq!(F::one().cube(), F::one(), "1^3 != 1");
  let two = F::one().double();
  assert_eq!(two.cube(), two * two * two, "2^3 != 8");
}

/// Run all tests on fields implementing Field.
pub fn test_field<F: Field>() {
  test_eq::<F>();
  test_conditional_select::<F>();
  test_add::<F>();
  test_sub::<F>();
  test_neg::<F>();
  test_mul::<F>();
  test_square::<F>();
  test_invert::<F>();
  test_sqrt::<F>();
  test_is_zero::<F>();
  test_cube::<F>();
}
