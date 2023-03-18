use k256::{
  elliptic_curve::sec1::{Tag, ToEncodedPoint},
  ProjectivePoint,
};

use bitcoin::XOnlyPublicKey;

/// Get the x coordinate of a non-infinity, even point. Panics on invalid input.
pub fn x(key: &ProjectivePoint) -> [u8; 32] {
  let encoded = key.to_encoded_point(true);
  assert_eq!(encoded.tag(), Tag::CompressedEvenY, "x coordinate of odd key");
  (*encoded.x().expect("point at infinity")).into()
}

/// Convert a non-infinite even point to a XOnlyPublicKey. Panics on invalid input.
pub fn x_only(key: &ProjectivePoint) -> XOnlyPublicKey {
  XOnlyPublicKey::from_slice(&x(key)).unwrap()
}

/// Make a point even by adding the generator until it is even. Returns the even point and the
/// amount of additions required.
pub fn make_even(mut key: ProjectivePoint) -> (ProjectivePoint, u64) {
  let mut c = 0;
  while key.to_encoded_point(true).tag() == Tag::CompressedOddY {
    key += ProjectivePoint::GENERATOR;
    c += 1;
  }
  (key, c)
}
