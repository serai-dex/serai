use rand_core::OsRng;

use subtle::Choice;
use group::ff::{Field, PrimeField};
use k256::{
  elliptic_curve::{
    FieldBytesEncoding,
    ops::Reduce,
    point::{AffineCoordinates, DecompressPoint},
  },
  AffinePoint, ProjectivePoint, Scalar, U256 as KU256,
};

use crate::PublicKey;

// Generates a key usable within tests
pub(crate) fn test_key() -> (Scalar, PublicKey) {
  loop {
    let key = Scalar::random(&mut OsRng);
    let point = ProjectivePoint::GENERATOR * key;
    if let Some(public_key) = PublicKey::new(point) {
      // While here, test `PublicKey::point` and its serialization functions
      assert_eq!(point, public_key.point());
      assert_eq!(PublicKey::from_eth_repr(public_key.eth_repr()).unwrap(), public_key);
      return (key, public_key);
    }
  }
}

#[test]
fn test_odd_key() {
  // We generate a valid key to ensure there's not some distinct reason this key is invalid
  let (_, key) = test_key();
  // We then take its point and negate it so its y-coordinate is odd
  let odd = -key.point();
  assert!(PublicKey::new(odd).is_none());
}

#[test]
fn test_non_mutual_key() {
  let mut x_coordinate = KU256::from(-(Scalar::ONE)).saturating_add(&KU256::ONE);

  let y_is_odd = Choice::from(0);
  let non_mutual = loop {
    if let Some(point) = Option::<AffinePoint>::from(AffinePoint::decompress(
      &FieldBytesEncoding::encode_field_bytes(&x_coordinate),
      y_is_odd,
    )) {
      break point;
    }
    x_coordinate = x_coordinate.saturating_add(&KU256::ONE);
  };
  let x_coordinate = non_mutual.x();
  assert!(<Scalar as Reduce<KU256>>::reduce_bytes(&x_coordinate).to_repr() != x_coordinate);

  // Even point whose x-coordinate isn't mutual to both fields (making it non-zero)
  assert!(PublicKey::new(non_mutual.into()).is_none());
}

#[test]
fn test_zero_key() {
  let y_is_odd = Choice::from(0);
  if let Some(A_affine) =
    Option::<AffinePoint>::from(AffinePoint::decompress(&[0; 32].into(), y_is_odd))
  {
    let A = ProjectivePoint::from(A_affine);
    assert!(PublicKey::new(A).is_none());
  }
}
