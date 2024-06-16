use std_shims::vec::Vec;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  traits::{IsIdentity, VartimeMultiscalarMul},
  scalar::Scalar,
  edwards::EdwardsPoint,
};

use monero_generators::{H, Generators};

use crate::{original, plus};

#[derive(Default)]
pub(crate) struct InternalBatchVerifier {
  pub(crate) g: Scalar,
  pub(crate) h: Scalar,
  pub(crate) g_bold: Vec<Scalar>,
  pub(crate) h_bold: Vec<Scalar>,
  pub(crate) other: Vec<(Scalar, EdwardsPoint)>,
}

impl InternalBatchVerifier {
  #[must_use]
  fn verify(self, G: EdwardsPoint, H: EdwardsPoint, generators: &Generators) -> bool {
    let capacity = 2 + self.g_bold.len() + self.h_bold.len() + self.other.len();
    let mut scalars = Vec::with_capacity(capacity);
    let mut points = Vec::with_capacity(capacity);

    scalars.push(self.g);
    points.push(G);

    scalars.push(self.h);
    points.push(H);

    for (i, g_bold) in self.g_bold.into_iter().enumerate() {
      scalars.push(g_bold);
      points.push(generators.G[i]);
    }

    for (i, h_bold) in self.h_bold.into_iter().enumerate() {
      scalars.push(h_bold);
      points.push(generators.H[i]);
    }

    for (scalar, point) in self.other {
      scalars.push(scalar);
      points.push(point);
    }

    EdwardsPoint::vartime_multiscalar_mul(scalars, points).is_identity()
  }
}

#[derive(Default)]
pub(crate) struct BulletproofsBatchVerifier(pub(crate) InternalBatchVerifier);
impl BulletproofsBatchVerifier {
  #[must_use]
  pub(crate) fn verify(self) -> bool {
    self.0.verify(ED25519_BASEPOINT_POINT, H(), original::GENERATORS())
  }
}

#[derive(Default)]
pub(crate) struct BulletproofsPlusBatchVerifier(pub(crate) InternalBatchVerifier);
impl BulletproofsPlusBatchVerifier {
  #[must_use]
  pub(crate) fn verify(self) -> bool {
    // Bulletproofs+ is written as per the paper, with G for the value and H for the mask
    // Monero uses H for the value and G for the mask
    self.0.verify(H(), ED25519_BASEPOINT_POINT, plus::GENERATORS())
  }
}

/// A batch verifier for Bulletproofs(+).
///
/// This uses a fixed layout such that all fixed points only incur a single point scaling,
/// regardless of the amounts of proofs verified. For all variable points (commitments), they're
/// accumulated with the fixed points into a single multiscalar multiplication.
#[derive(Default)]
pub struct BatchVerifier {
  pub(crate) original: BulletproofsBatchVerifier,
  pub(crate) plus: BulletproofsPlusBatchVerifier,
}
impl BatchVerifier {
  /// Create a new batch verifier.
  pub fn new() -> Self {
    Self {
      original: BulletproofsBatchVerifier(InternalBatchVerifier::default()),
      plus: BulletproofsPlusBatchVerifier(InternalBatchVerifier::default()),
    }
  }

  /// Verify all of the proofs queued within this batch verifier.
  ///
  /// This uses a variable-time multiscalar multiplication internally.
  #[must_use]
  pub fn verify(self) -> bool {
    self.original.verify() && self.plus.verify()
  }
}
