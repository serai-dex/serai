use std_shims::sync::OnceLock;

use dalek_ff_group::{Scalar, EdwardsPoint};

use crate::{INV_EIGHT as DALEK_INV_EIGHT, H as DALEK_H, Commitment, hash, hash_to_scalar as dalek_hash};

#[inline]
pub(crate) fn INV_EIGHT() -> Scalar {
  Scalar(DALEK_INV_EIGHT())
}

// Monero starts BP+ transcripts with the following constant.
static TRANSCRIPT_CELL: OnceLock<[u8; 32]> = OnceLock::new();
pub(crate) fn TRANSCRIPT() -> [u8; 32] {
  // Why this uses a hash_to_point is completely unknown.
  *TRANSCRIPT_CELL.get_or_init(|| {
    raw_hash_to_point(hash(b"bulletproof_plus_transcript")).compress().to_bytes()
  })
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar(dalek_hash(data))
}

// Hash the commitments.
// Monero avoids torsion checks on the commitments by clearing torsion, making it irrelevant if it
// was ever present or not.
pub(crate) fn hash_commitments<C: IntoIterator<Item = DalekPoint>>(
  commitments: C,
) -> Scalar {
  hash_to_scalar(&commitments.into_iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>())
}

// TRANSCRIPT isn't a Scalar, so we need this for the first hash
fn initial_transcript<C: IntoIterator<Item = DalekPoint>>(commitments: C) -> Scalar {
  hash_to_scalar(&[TRANSCRIPT().as_ref(), &hash_commitments(commitments).to_bytes()].concat())
}
