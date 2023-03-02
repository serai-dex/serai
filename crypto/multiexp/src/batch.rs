use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::{multiexp, multiexp_vartime};

// Flatten the contained statements to a single Vec.
// Wrapped in Zeroizing in case any of the included statements contain private values.
#[allow(clippy::type_complexity)]
fn flat<Id: Copy + Zeroize, G: Group + Zeroize>(
  slice: &[(Id, Vec<(G::Scalar, G)>)],
) -> Zeroizing<Vec<(G::Scalar, G)>>
where
  <G as Group>::Scalar: PrimeFieldBits + Zeroize,
{
  Zeroizing::new(slice.iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>())
}

/// A batch verifier intended to verify a series of statements are each equivalent to zero.
#[allow(clippy::type_complexity)]
#[derive(Clone, Zeroize)]
pub struct BatchVerifier<Id: Copy + Zeroize, G: Group + Zeroize>
where
  <G as Group>::Scalar: PrimeFieldBits + Zeroize,
{
  split: u64,
  statements: Zeroizing<Vec<(Id, Vec<(G::Scalar, G)>)>>,
}

impl<Id: Copy + Zeroize, G: Group + Zeroize> BatchVerifier<Id, G>
where
  <G as Group>::Scalar: PrimeFieldBits + Zeroize,
{
  /// Create a new batch verifier, expected to verify the following amount of statements.
  /// This is a size hint and is not required to be accurate.
  pub fn new(capacity: usize) -> BatchVerifier<Id, G> {
    BatchVerifier { split: 0, statements: Zeroizing::new(Vec::with_capacity(capacity)) }
  }

  /// Queue a statement for batch verification.
  pub fn queue<R: RngCore + CryptoRng, I: IntoIterator<Item = (G::Scalar, G)>>(
    &mut self,
    rng: &mut R,
    id: Id,
    pairs: I,
  ) {
    // If this is the first time we're queueing a value, grab a u64 (AKA 64 bits) to determine
    // which side to handle odd splits with during blame (preventing malicious actors from gaming
    // the system by maximizing the round length)
    if self.statements.len() == 0 {
      self.split = rng.next_u64();
    }

    // Define a unique scalar factor for this set of variables so individual items can't overlap
    let u = if self.statements.is_empty() {
      G::Scalar::one()
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

    self
      .statements
      .push((id, pairs.into_iter().map(|(scalar, point)| (scalar * u, point)).collect()));
  }

  /// Perform batch verification, returning a boolean of if the statements equaled zero.
  #[must_use]
  pub fn verify(&self) -> bool {
    multiexp(&flat(&self.statements)).is_identity().into()
  }

  /// Perform batch verification in variable time.
  #[must_use]
  pub fn verify_vartime(&self) -> bool {
    multiexp_vartime(&flat(&self.statements)).is_identity().into()
  }

  /// Perform a binary search to identify which statement does not equal 0, returning None if all
  /// statements do. This function will only return the ID of one invalid statement, even if
  /// multiple are invalid.
  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime(&self) -> Option<Id> {
    let mut slice = self.statements.as_slice();
    let mut split_side = self.split;

    while slice.len() > 1 {
      let mut split = slice.len() / 2;
      // If there's an odd number of elements, this can be gamed to increase the amount of rounds
      // For [0, 1, 2], where 2 is invalid, this will take three rounds
      // ([0], [1, 2]), then ([1], [2]), before just 2
      // If 1 and 2 were valid, this would've only taken 2 rounds to complete
      // To prevent this from being gamed, if there's an odd number of elements, randomize which
      // side the split occurs on
      if slice.len() % 2 == 1 {
        split += usize::try_from(split_side & 1).unwrap();
        split_side >>= 1;
      }

      if multiexp_vartime(&flat(&slice[.. split])).is_identity().into() {
        slice = &slice[split ..];
      } else {
        slice = &slice[.. split];
      }
    }

    slice
      .get(0)
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
