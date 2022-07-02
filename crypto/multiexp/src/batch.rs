use rand_core::{RngCore, CryptoRng};

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::{multiexp, multiexp_vartime};

#[cfg(feature = "batch")]
pub struct BatchVerifier<Id: Copy, G: Group>(Vec<(Id, Vec<(G::Scalar, G)>)>);

#[cfg(feature = "batch")]
impl<Id: Copy, G: Group> BatchVerifier<Id, G> where <G as Group>::Scalar: PrimeFieldBits {
  pub fn new(capacity: usize) -> BatchVerifier<Id, G> {
    BatchVerifier(Vec::with_capacity(capacity))
  }

  pub fn queue<
    R: RngCore + CryptoRng,
    I: IntoIterator<Item = (G::Scalar, G)>
  >(&mut self, rng: &mut R, id: Id, pairs: I) {
    // Define a unique scalar factor for this set of variables so individual items can't overlap
    let u = if self.0.len() == 0 {
      G::Scalar::one()
    } else {
      let mut weight = G::Scalar::random(&mut *rng);
      // Ensure it's non-zero, as a zero scalar would cause this item to pass no matter what
      while weight.is_zero().into() {
        weight = G::Scalar::random(&mut *rng);
      }
      weight
    };
    self.0.push((id, pairs.into_iter().map(|(scalar, point)| (scalar * u, point)).collect()));
  }

  pub fn verify(&self) -> bool {
    multiexp(
      &self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>()
    ).is_identity().into()
  }

  pub fn verify_vartime(&self) -> bool {
    multiexp_vartime(
      &self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>()
    ).is_identity().into()
  }

  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime(&self) -> Option<Id> {
    let mut slice = self.0.as_slice();
    while slice.len() > 1 {
      let split = slice.len() / 2;
      if multiexp_vartime(
        &slice[.. split].iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>()
      ).is_identity().into() {
        slice = &slice[split ..];
      } else {
        slice = &slice[.. split];
      }
    }

    slice.get(0).filter(
      |(_, value)| !bool::from(multiexp_vartime(value).is_identity())
    ).map(|(id, _)| *id)
  }

  pub fn verify_with_vartime_blame(&self) -> Result<(), Id> {
    if self.verify() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    }
  }

  pub fn verify_vartime_with_vartime_blame(&self) -> Result<(), Id> {
    if self.verify_vartime() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    }
  }
}
