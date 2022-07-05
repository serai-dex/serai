// use sha3::{Digest, Keccak256};

// use group::Group;
// use k256::{
//   elliptic_curve::{ops::Reduce, DecompressPoint, sec1::ToEncodedPoint},
//   U256, Scalar, ProjectivePoint, AffinePoint
// };

// use modular_frost::{curve::Secp256k1, algorithm::Hram};

// fn keccak256(data: &[u8]) -> [u8; 32] {
//   Keccak256::digest(data).try_into().unwrap()
// }

// fn hash_to_scalar(data: &[u8]) -> Scalar {
//   Scalar::from_uint_reduced(U256::from_be_slice(&keccak256(data)))
// }

// fn address(point: &ProjectivePoint) -> [u8; 20] {
//   keccak256(point.to_encoded_point(false).as_ref())[0 .. 20].try_into().unwrap()
// }

// fn ecrecover(message: Scalar, v: u8, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
//   if r.is_zero().into() || s.is_zero().into() {
//     return None;
//   }

//   #[allow(non_snake_case)]
//   let R = AffinePoint::decompress(&r.to_bytes(), v.into());
//   #[allow(non_snake_case)]
//   if let Some(R) = Option::<AffinePoint>::from(R) {
//     #[allow(non_snake_case)]
//     let R = ProjectivePoint::from(R);

//     let r = r.invert().unwrap();
//     let u1 = ProjectivePoint::GENERATOR * (-message * r);
//     let u2 = R * (s * r);
//     let key: ProjectivePoint = u1 + u2;
//     if !bool::from(key.is_identity()) {
//       return Some(address(&key));
//     }
//   }
//   return None;
// }

// #[derive(Clone)]
// struct EthereumHram {}
// impl Hram<Secp256k1> for EthereumHram {
//   #[allow(non_snake_case)]
//   fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
//     Scalar::from_uint_reduced(
//       U256::from_be_slice(
//         &keccak256(&[&address(R), A.to_encoded_point(true).as_ref(), m].concat())
//       )
//     )
//   }
// }