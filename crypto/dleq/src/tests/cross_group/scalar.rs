use rand_core::OsRng;

use ff::{Field, PrimeField};

use k256::Scalar as K256Scalar;
use dalek_ff_group::Scalar as DalekScalar;

use crate::cross_group::scalar::{scalar_normalize, scalar_convert};

#[test]
fn test_scalar() {
  assert_eq!(
    scalar_normalize::<_, DalekScalar>(K256Scalar::ZERO),
    (K256Scalar::ZERO, DalekScalar::ZERO)
  );

  assert_eq!(
    scalar_normalize::<_, DalekScalar>(K256Scalar::ONE),
    (K256Scalar::ONE, DalekScalar::ONE)
  );

  let mut initial;
  while {
    initial = K256Scalar::random(&mut OsRng);
    let (k, ed) = scalar_normalize::<_, DalekScalar>(initial);

    // The initial scalar should equal the new scalar with Ed25519's capacity
    let mut initial_bytes = initial.to_repr().to_vec();
    // Drop the first 4 bits to hit 252
    initial_bytes[0] &= 0b0000_1111;
    let k_bytes = k.to_repr().to_vec();
    assert_eq!(initial_bytes, k_bytes);

    let mut ed_bytes = ed.to_repr().as_ref().to_vec();
    // Reverse to big endian
    ed_bytes.reverse();
    assert_eq!(k_bytes, ed_bytes);

    // Verify conversion works as expected
    assert_eq!(scalar_convert::<_, DalekScalar>(k), Some(ed));

    // Run this test again if this secp256k1 scalar didn't have any bits cleared
    initial == k
  } {}
  // Verify conversion returns None when the scalar isn't mutually valid
  assert!(scalar_convert::<_, DalekScalar>(initial).is_none());
}
