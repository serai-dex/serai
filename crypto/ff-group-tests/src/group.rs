use group::{
  ff::{Field, PrimeFieldBits},
  Group,
  prime::PrimeGroup,
};

use crate::prime_field::{test_prime_field, test_prime_field_bits};

/// Test equality.
pub fn test_eq<G: Group>() {
  assert_eq!(G::identity(), G::identity(), "identity != identity");
  assert_eq!(G::generator(), G::generator(), "generator != generator");
  assert!(G::identity() != G::generator(), "identity != generator");
}

/// Test identity.
pub fn test_identity<G: Group>() {
  assert!(bool::from(G::identity().is_identity()), "identity wasn't identity");
  assert!(
    bool::from((G::identity() + G::identity()).is_identity()),
    "identity + identity wasn't identity"
  );
  assert!(
    bool::from((G::generator() - G::generator()).is_identity()),
    "generator - generator wasn't identity"
  );
  assert!(!bool::from(G::generator().is_identity()), "is_identity claimed generator was identity");
}

/// Sanity check the generator.
pub fn test_generator<G: Group>() {
  assert!(G::generator() != G::identity(), "generator was identity");
  assert!(
    (G::generator() + G::generator()) != G::generator(),
    "generator added to itself identity"
  );
}

/// Test doubling of group elements.
pub fn test_double<G: Group>() {
  assert!(bool::from(G::identity().double().is_identity()), "identity.double() wasn't identity");
  assert_eq!(
    G::generator() + G::generator(),
    G::generator().double(),
    "generator + generator != generator.double()"
  );
}

/// Test addition.
pub fn test_add<G: Group>() {
  assert_eq!(G::identity() + G::identity(), G::identity(), "identity + identity != identity");
  assert_eq!(G::identity() + G::generator(), G::generator(), "identity + generator != generator");
  assert_eq!(G::generator() + G::identity(), G::generator(), "generator + identity != generator");

  let two = G::generator().double();
  assert_eq!(G::generator() + G::generator(), two, "generator + generator != two");
  let four = two.double();
  assert_eq!(
    G::generator() + G::generator() + G::generator() + G::generator(),
    four,
    "generator + generator + generator + generator != four"
  );
}

/// Test summation.
pub fn test_sum<G: Group>() {
  assert_eq!(
    [G::generator(), G::generator()].iter().sum::<G>(),
    G::generator().double(),
    "[generator, generator].sum() != two"
  );
}

/// Test negation.
pub fn test_neg<G: Group>() {
  assert_eq!(G::identity(), G::identity().neg(), "identity != -identity");
  assert_eq!(
    G::generator() + G::generator().neg(),
    G::identity(),
    "generator + -generator != identity"
  );
}

/// Test subtraction.
pub fn test_sub<G: Group>() {
  assert_eq!(G::generator() - G::generator(), G::identity(), "generator - generator != identity");
  let two = G::generator() + G::generator();
  assert_eq!(two - G::generator(), G::generator(), "two - one != one");
}

/// Test scalar multiplication
pub fn test_mul<G: Group>() {
  assert_eq!(G::generator() * G::Scalar::from(0), G::identity(), "generator * 0 != identity");
  assert_eq!(G::generator() * G::Scalar::from(1), G::generator(), "generator * 1 != generator");
  assert_eq!(
    G::generator() * G::Scalar::from(2),
    G::generator() + G::generator(),
    "generator * 2 != generator + generator"
  );
  assert_eq!(G::identity() * G::Scalar::from(2), G::identity(), "identity * 2 != identity");
}

/// Test `((order - 1) * G) + G == identity`.
pub fn test_order<G: Group>() {
  let minus_one = G::generator() * (G::Scalar::zero() - G::Scalar::one());
  assert!(minus_one != G::identity(), "(modulus - 1) * G was identity");
  assert_eq!(minus_one + G::generator(), G::identity(), "((modulus - 1) * G) + G wasn't identity");
}

/// Run all tests on groups implementing Group.
pub fn test_group<G: Group>() {
  test_prime_field::<G::Scalar>();

  test_eq::<G>();
  test_identity::<G>();
  test_generator::<G>();
  test_double::<G>();
  test_add::<G>();
  test_sum::<G>();
  test_neg::<G>();
  test_sub::<G>();
  test_mul::<G>();
  test_order::<G>();
}

/// Test encoding and decoding of group elements.
pub fn test_encoding<G: PrimeGroup>() {
  let test = |point: G, msg| {
    let bytes = point.to_bytes();
    let mut repr = G::Repr::default();
    repr.as_mut().copy_from_slice(bytes.as_ref());
    assert_eq!(point, G::from_bytes(&repr).unwrap(), "{msg} couldn't be encoded and decoded");
    assert_eq!(
      point,
      G::from_bytes_unchecked(&repr).unwrap(),
      "{msg} couldn't be encoded and decoded",
    );
  };
  test(G::identity(), "identity");
  test(G::generator(), "generator");
  test(G::generator() + G::generator(), "(generator * 2)");
}

/// Run all tests on groups implementing PrimeGroup (Group + GroupEncoding).
pub fn test_prime_group<G: PrimeGroup>() {
  test_group::<G>();

  test_encoding::<G>();
}

/// Run all tests offered by this crate on the group.
pub fn test_prime_group_bits<G: PrimeGroup>()
where
  G::Scalar: PrimeFieldBits,
{
  test_prime_field_bits::<G::Scalar>();
  test_prime_group::<G>();
}

// Run these tests against k256/p256
// This ensures that these tests are well formed and won't error for valid implementations,
// assuming the validity of k256/p256
// While k256 and p256 may be malformed in a way which coincides with a faulty test, this is
// considered unlikely
// The other option, not running against any libraries, would leave faulty tests completely
// undetected

#[test]
fn test_k256() {
  test_prime_group_bits::<k256::ProjectivePoint>();
}

#[test]
fn test_p256() {
  test_prime_group_bits::<p256::ProjectivePoint>();
}
