use subtle::ConditionallySelectable;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use group::ff::{Field, PrimeField};
use dalek_ff_group::FieldElement;

use crate::hash;

/// Monero's hash to point function, as named `ge_fromfe_frombytes_vartime`.
pub fn hash_to_point(bytes: [u8; 32]) -> EdwardsPoint {
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);

  let v = FieldElement::from_square(hash(&bytes)).double();
  let w = v + FieldElement::one();
  let x = w.square() + (-A.square() * v);

  // This isn't the complete X, yet its initial value
  // We don't calculate the full X, and instead solely calculate Y, letting dalek reconstruct X
  // While inefficient, it solves API boundaries and reduces the amount of work done here
  #[allow(non_snake_case)]
  let X = {
    let u = w;
    let v = x;
    let v3 = v * v * v;
    let uv3 = u * v3;
    let v7 = v3 * v3 * v;
    let uv7 = u * v7;
    uv3 * uv7.pow((-FieldElement::from(5u8)) * FieldElement::from(8u8).invert().unwrap())
  };
  let x = X.square() * x;

  let y = w - x;
  let non_zero_0 = !y.is_zero();
  let y_if_non_zero_0 = w + x;
  let sign = non_zero_0 & (!y_if_non_zero_0.is_zero());

  let mut z = -A;
  z *= FieldElement::conditional_select(&v, &FieldElement::from(1u8), sign);
  #[allow(non_snake_case)]
  let Z = z + w;
  #[allow(non_snake_case)]
  let mut Y = z - w;

  Y *= Z.invert().unwrap();
  let mut bytes = Y.to_repr();
  bytes[31] |= sign.unwrap_u8() << 7;

  CompressedEdwardsY(bytes).decompress().unwrap().mul_by_cofactor()
}
