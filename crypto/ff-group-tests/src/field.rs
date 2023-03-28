use rand_core::RngCore;
use group::ff::Field;

/// Perform basic tests on equality.
pub fn test_eq<F: Field>() {
  let zero = F::ZERO;
  let one = F::ONE;

  assert!(zero != one, "0 == 1");
  assert!(!bool::from(zero.ct_eq(&one)), "0 ct_eq 1");

  assert_eq!(zero, F::ZERO, "0 != 0");
  assert!(bool::from(zero.ct_eq(&F::ZERO)), "0 !ct_eq 0");

  assert_eq!(one, F::ONE, "1 != 1");
  assert!(bool::from(one.ct_eq(&F::ONE)), "1 !ct_eq 1");
}

/// Verify conditional selection works. Doesn't verify it's actually constant time.
pub fn test_conditional_select<F: Field>() {
  let zero = F::ZERO;
  let one = F::ONE;
  assert_eq!(F::conditional_select(&zero, &one, 0.into()), zero, "couldn't select when false");
  assert_eq!(F::conditional_select(&zero, &one, 1.into()), one, "couldn't select when true");
}

/// Perform basic tests on addition.
pub fn test_add<F: Field>() {
  assert_eq!(F::ZERO + F::ZERO, F::ZERO, "0 + 0 != 0");
  assert_eq!(F::ZERO + F::ONE, F::ONE, "0 + 1 != 1");
  assert_eq!(F::ONE + F::ZERO, F::ONE, "1 + 0 != 1");
  // Only PrimeField offers From<u64>
  // Accordingly, we assume either double or addition is correct
  // They either have to be matchingly correct or matchingly incorrect, yet we can't
  // reliably determine that here
  assert_eq!(F::ONE + F::ONE, F::ONE.double(), "1 + 1 != 2");
}

/// Perform basic tests on sum.
pub fn test_sum<F: Field>() {
  assert_eq!((&[] as &[F]).iter().sum::<F>(), F::ZERO, "[].sum() != 0");
  assert_eq!([F::ZERO].iter().sum::<F>(), F::ZERO, "[0].sum() != 0");
  assert_eq!([F::ONE].iter().sum::<F>(), F::ONE, "[1].sum() != 1");

  let two = F::ONE + F::ONE;
  assert_eq!([F::ONE, F::ONE].iter().sum::<F>(), two, "[1, 1].sum() != 2");
  assert_eq!([two, F::ONE].iter().sum::<F>(), two + F::ONE, "[2, 1].sum() != 3");
  assert_eq!([two, F::ZERO, F::ONE].iter().sum::<F>(), two + F::ONE, "[2, 0, 1].sum() != 3");
}

/// Perform basic tests on subtraction.
pub fn test_sub<F: Field>() {
  #[allow(clippy::eq_op)]
  let expr = F::ZERO - F::ZERO;
  assert_eq!(expr, F::ZERO, "0 - 0 != 0");
  assert_eq!(F::ONE - F::ZERO, F::ONE, "1 - 0 != 1");
  #[allow(clippy::eq_op)]
  let expr = F::ONE - F::ONE;
  assert_eq!(expr, F::ZERO, "1 - 1 != 0");
}

/// Perform basic tests on negation.
pub fn test_neg<F: Field>() {
  assert_eq!(-F::ZERO, F::ZERO, "-0 != 0");
  assert_eq!(-(-F::ONE), F::ONE, "-(-1) != 1");
  assert_eq!(F::ONE + (-F::ONE), F::ZERO, "1 + -1 != 0");
  assert_eq!(F::ONE - (-F::ONE), F::ONE.double(), "1 - -1 != 2");
}

/// Perform basic tests on multiplication.
pub fn test_mul<F: Field>() {
  assert_eq!(F::ZERO * F::ZERO, F::ZERO, "0 * 0 != 0");
  assert_eq!(F::ONE * F::ZERO, F::ZERO, "1 * 0 != 0");
  assert_eq!(F::ONE * F::ONE, F::ONE, "1 * 1 != 1");
  let two = F::ONE.double();
  assert_eq!(two * (two + F::ONE), two + two + two, "2 * 3 != 6");
}

/// Perform basic tests on product.
pub fn test_product<F: Field>() {
  assert_eq!((&[] as &[F]).iter().product::<F>(), F::ONE, "[].product() != 1");
  assert_eq!([F::ZERO].iter().product::<F>(), F::ZERO, "[0].product() != 0");
  assert_eq!([F::ONE].iter().product::<F>(), F::ONE, "[1].product() != 1");

  assert_eq!([F::ONE, F::ONE].iter().product::<F>(), F::ONE, "[1, 1].product() != 2");
  let two = F::ONE + F::ONE;
  assert_eq!([two, F::ONE].iter().product::<F>(), two, "[2, 1].product() != 2");
  assert_eq!([two, two].iter().product::<F>(), two + two, "[2, 2].product() != 4");
  assert_eq!([two, two, F::ONE].iter().product::<F>(), two + two, "[2, 2, 1].product() != 4");
  assert_eq!([two, F::ZERO, F::ONE].iter().product::<F>(), F::ZERO, "[2, 0, 1].product() != 0");
}

/// Perform basic tests on the square function.
pub fn test_square<F: Field>() {
  assert_eq!(F::ZERO.square(), F::ZERO, "0^2 != 0");
  assert_eq!(F::ONE.square(), F::ONE, "1^2 != 1");
  let two = F::ONE.double();
  assert_eq!(two.square(), two + two, "2^2 != 4");
  let three = two + F::ONE;
  assert_eq!(three.square(), three * three, "3^2 != 9");
}

/// Perform basic tests on the invert function.
pub fn test_invert<F: Field>() {
  assert!(bool::from(F::ZERO.invert().is_none()), "0.invert() is some");
  assert_eq!(F::ONE.invert().unwrap(), F::ONE, "1.invert() != 1");

  let two = F::ONE.double();
  let three = two + F::ONE;
  assert_eq!(two * three.invert().unwrap() * three, two, "2 * 3.invert() * 3 != 2");
}

/// Perform basic tests on the sqrt function.
pub fn test_sqrt<F: Field>() {
  assert_eq!(F::ZERO.sqrt().unwrap(), F::ZERO, "sqrt(0) != 0");
  assert_eq!(F::ONE.sqrt().unwrap(), F::ONE, "sqrt(1) != 1");

  let mut has_root = F::ONE.double();
  while bool::from(has_root.sqrt().is_none()) {
    has_root += F::ONE;
  }
  let root = has_root.sqrt().unwrap();
  assert_eq!(root * root, has_root, "sqrt(x)^2 != x");
}

/// Perform basic tests on the is_zero functions.
pub fn test_is_zero<F: Field>() {
  assert!(bool::from(F::ZERO.is_zero()), "0 is not 0");
  assert!(F::ZERO.is_zero_vartime(), "0 is not 0");
}

/// Perform basic tests on the cube function.
pub fn test_cube<F: Field>() {
  assert_eq!(F::ZERO.cube(), F::ZERO, "0^3 != 0");
  assert_eq!(F::ONE.cube(), F::ONE, "1^3 != 1");
  let two = F::ONE.double();
  assert_eq!(two.cube(), two * two * two, "2^3 != 8");
}

/// Test random.
pub fn test_random<R: RngCore, F: Field>(rng: &mut R) {
  let a = F::random(&mut *rng);

  // Run up to 128 times so small fields, which may occasionally return the same element twice,
  // are statistically unlikely to fail
  // Field of order 1 will always fail this test due to lack of distinct elements to sample
  // from
  let mut pass = false;
  for _ in 0 .. 128 {
    let b = F::random(&mut *rng);
    // This test passes if a distinct element is returned at least once
    if b != a {
      pass = true;
    }
  }
  assert!(pass, "random always returned the same value");
}

/// Run all tests on fields implementing Field.
pub fn test_field<R: RngCore, F: Field>(rng: &mut R) {
  test_eq::<F>();
  test_conditional_select::<F>();

  test_add::<F>();
  test_sum::<F>();

  test_sub::<F>();
  test_neg::<F>();

  test_mul::<F>();
  test_product::<F>();

  test_square::<F>();
  test_invert::<F>();
  test_sqrt::<F>();
  test_is_zero::<F>();

  test_cube::<F>();

  test_random::<R, F>(rng);
}
