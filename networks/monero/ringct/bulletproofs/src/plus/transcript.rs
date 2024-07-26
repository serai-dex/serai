use std_shims::{sync::LazyLock, vec::Vec};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use monero_generators::hash_to_point;
use monero_primitives::{keccak256, keccak256_to_scalar};

// Monero starts BP+ transcripts with the following constant.
// Why this uses a hash_to_point is completely unknown.
pub(crate) static TRANSCRIPT: LazyLock<[u8; 32]> =
  LazyLock::new(|| hash_to_point(keccak256(b"bulletproof_plus_transcript")).compress().to_bytes());

pub(crate) fn initial_transcript(commitments: core::slice::Iter<'_, EdwardsPoint>) -> Scalar {
  let commitments_hash =
    keccak256_to_scalar(commitments.flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>());
  keccak256_to_scalar([TRANSCRIPT.as_ref(), &commitments_hash.to_bytes()].concat())
}
