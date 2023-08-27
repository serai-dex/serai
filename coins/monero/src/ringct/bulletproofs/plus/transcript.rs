use std_shims::{sync::OnceLock, vec::Vec};

use dalek_ff_group::{Scalar, EdwardsPoint};

use monero_generators::{hash_to_point as raw_hash_to_point};
use crate::{hash, hash_to_scalar as dalek_hash};

// Monero starts BP+ transcripts with the following constant.
static TRANSCRIPT_CELL: OnceLock<[u8; 32]> = OnceLock::new();
pub(crate) fn TRANSCRIPT() -> [u8; 32] {
  // Why this uses a hash_to_point is completely unknown.
  *TRANSCRIPT_CELL
    .get_or_init(|| raw_hash_to_point(hash(b"bulletproof_plus_transcript")).compress().to_bytes())
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar(dalek_hash(data))
}

pub(crate) fn initial_transcript(commitments: core::slice::Iter<'_, EdwardsPoint>) -> Scalar {
  let commitments_hash =
    hash_to_scalar(&commitments.flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>());
  hash_to_scalar(&[TRANSCRIPT().as_ref(), &commitments_hash.to_bytes()].concat())
}
