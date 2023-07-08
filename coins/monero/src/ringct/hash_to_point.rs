use curve25519_dalek::edwards::EdwardsPoint;

pub use monero_generators::{hash_to_point as raw_hash_to_point};

/// Monero's hash to point function, as named `ge_fromfe_frombytes_vartime`.
pub fn hash_to_point(key: EdwardsPoint) -> EdwardsPoint {
  raw_hash_to_point(key.compress().to_bytes())
}
