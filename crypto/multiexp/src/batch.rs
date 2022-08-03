use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::{multiexp, multiexp_vartime};

#[cfg(feature = "batch")]
#[derive(Clone, Zeroize)]
pub struct BatchVerifier<Id: Copy + Zeroize, G: Group + Zeroize>(Vec<(Id, Vec<(G::Scalar, G)>)>);

#[cfg(feature = "batch")]
impl<Id: Copy + Zeroize, G: Group + Zeroize> BatchVerifier<Id, G>
where
  <G as Group>::Scalar: PrimeFieldBits + Zeroize,
{
  pub fn new(capacity: usize) -> BatchVerifier<Id, G> {
    BatchVerifier(Vec::with_capacity(capacity))
  }

  pub fn queue<R: RngCore + CryptoRng, I: IntoIterator<Item = (G::Scalar, G)>>(
    &mut self,
    rng: &mut R,
    id: Id,
    pairs: I,
  ) {
    // Define a unique scalar factor for this set of variables so individual items can't overlap
    let u = if self.0.is_empty() {
      G::Scalar::one()
    } else {
      let mut weight;
      // Ensure it's non-zero, as a zero scalar would cause this item to pass no matter what
      while {
        weight = G::Scalar::random(&mut *rng);
        weight.is_zero().into()
      } {}
      weight
    };
    self.0.push((id, pairs.into_iter().map(|(scalar, point)| (scalar * u, point)).collect()));
  }

  #[must_use]
  pub fn verify_core(&self) -> bool {
    let mut flat = self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>();
    let res = multiexp(&flat).is_identity().into();
    flat.zeroize();
    res
  }

  pub fn verify(mut self) -> bool {
    let res = self.verify_core();
    self.zeroize();
    res
  }

  #[must_use]
  pub fn verify_vartime(&self) -> bool {
    multiexp_vartime(&self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>())
      .is_identity()
      .into()
  }

  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime(&self) -> Option<Id> {
    let mut slice = self.0.as_slice();
    while slice.len() > 1 {
      let split = slice.len() / 2;
      if multiexp_vartime(
        &slice[.. split].iter().flat_map(|pairs| pairs.1.iter()).cloned().collect::<Vec<_>>(),
      )
      .is_identity()
      .into()
      {
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

  pub fn verify_with_vartime_blame(mut self) -> Result<(), Id> {
    let res = if self.verify_core() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    };
    self.zeroize();
    res
  }

  pub fn verify_vartime_with_vartime_blame(&self) -> Result<(), Id> {
    if self.verify_vartime() {
      Ok(())
    } else {
      Err(self.blame_vartime().unwrap())
    }
  }
}
