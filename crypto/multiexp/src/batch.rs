use std_shims::vec::Vec;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::{multiexp, multiexp_vartime};

// Flatten the contained statements to a single Vec.
// Wrapped in Zeroizing in case any of the included statements contain private values.
#[allow(clippy::type_complexity)]
fn flat<Id: Copy + Zeroize, G: Group<Scalar: PrimeFieldBits + Zeroize> + Zeroize>(
  slice: &[(Id, Vec<(G::Scalar, G)>)],
) -> Zeroizing<Vec<(G::Scalar, G)>> {
  Zeroizing::new(slice.iter().flat_map(|pairs| pairs.1.iter()).copied().collect::<Vec<_>>())
}

/// A batch verifier intended to verify a series of statements are each equivalent to zero.
#[allow(clippy::type_complexity)]
#[derive(Clone, Zeroize)]
pub struct BatchVerifier<Id: Copy + Zeroize, G: Group<Scalar: PrimeFieldBits + Zeroize> + Zeroize>(
  Zeroizing<Vec<(Id, Vec<(G::Scalar, G)>)>>,
);

impl<Id: Copy + Zeroize, G: Group<Scalar: PrimeFieldBits + Zeroize> + Zeroize>
  BatchVerifier<Id, G>
{
  /// Create a new batch verifier, expected to verify the following amount of statements.
  ///
  /// `capacity` is a size hint and is not required to be accurate.
  pub fn new(capacity: usize) -> BatchVerifier<Id, G> {
    BatchVerifier(Zeroizing::new(Vec::with_capacity(capacity)))
  }

  /// Queue a statement for batch verification.
  pub fn queue<R: RngCore + CryptoRng, I: IntoIterator<Item = (G::Scalar, G)>>(
    &mut self,
    rng: &mut R,
    id: Id,
    pairs: I,
  ) {
    // Define a unique scalar factor for this set of variables so individual items can't overlap
    let u = if self.0.is_empty() {
      G::Scalar::ONE
    } else {
      let mut weight;
      while {
        // Generate a random scalar
        weight = G::Scalar::random(&mut *rng);

        // Clears half the bits, maintaining security, to minimize scalar additions
        // Is not practically faster for whatever reason
        /*
        // Generate a random scalar
        let mut repr = G::Scalar::random(&mut *rng).to_repr();

        // Calculate the amount of bytes to clear. We want to clear less than half
        let repr_len = repr.as_ref().len();
        let unused_bits = (repr_len * 8) - usize::try_from(G::Scalar::CAPACITY).unwrap();
        // Don't clear any partial bytes
        let to_clear = (repr_len / 2) - ((unused_bits + 7) / 8);

        // Clear a safe amount of bytes
        for b in &mut repr.as_mut()[.. to_clear] {
          *b = 0;
        }

        // Ensure these bits are used as the low bits so low scalars multiplied by this don't
        // become large scalars
        weight = G::Scalar::from_repr(repr).unwrap();
        // Tests if any bit we supposedly just cleared is set, and if so, reverses it
        // Not a security issue if this fails, just a minor performance hit at ~2^-120 odds
        if weight.to_le_bits().iter().take(to_clear * 8).any(|bit| *bit) {
          repr.as_mut().reverse();
          weight = G::Scalar::from_repr(repr).unwrap();
        }
        */

        // Ensure it's non-zero, as a zero scalar would cause this item to pass no matter what
        weight.is_zero().into()
      } {}
      weight
    };

    self.0.push((id, pairs.into_iter().map(|(scalar, point)| (scalar * u, point)).collect()));
  }

  /// Perform batch verification, returning a boolean of if the statements equaled zero.
  #[must_use]
  pub fn verify(&self) -> bool {
    multiexp(&flat(&self.0)).is_identity().into()
  }

  /// Perform batch verification in variable time.
  #[must_use]
  pub fn verify_vartime(&self) -> bool {
    multiexp_vartime(&flat(&self.0)).is_identity().into()
  }

  /// Perform a binary search to identify which statement does not equal 0, returning None if all
  /// statements do.
  ///
  /// This function will only return the ID of one invalid statement, even if multiple are invalid.
  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime(&self) -> Option<Id> {
    let mut slice = self.0.as_slice();
    while slice.len() > 1 {
      let split = slice.len() / 2;
      if multiexp_vartime(&flat(&slice[.. split])).is_identity().into() {
        slice = &slice[split ..];
      } else {
        slice = &slice[.. split];
      }
    }

    slice
      .first()
      .filter(|(_, value)| !bool::from(multiexp_vartime(value).is_identity()))
      .map(|(id, _)| *id)
  }

  /// Perform constant time batch verification, and if verification fails, identify one faulty
  /// statement in variable time.
  pub fn verify_with_vartime_blame(&self) -> Result<(), Id> {
    if self.verify() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    }
  }

  /// Perform variable time batch verification, and if verification fails, identify one faulty
  /// statement in variable time.
  pub fn verify_vartime_with_vartime_blame(&self) -> Result<(), Id> {
    if self.verify_vartime() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    }
  }
}
