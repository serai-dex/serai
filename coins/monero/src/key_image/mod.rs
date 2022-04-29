use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use crate::hash_to_point;

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use crate::key_image::multisig::{generate_share, verify_share};

pub fn generate(secret: &Scalar) -> EdwardsPoint {
  secret * hash_to_point(&(secret * &ED25519_BASEPOINT_TABLE))
}
