use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::{multiexp, multiexp_vartime};

#[cfg(feature = "batch")]
#[derive(Clone)]
pub struct BatchVerifier<Id: Copy, G: Group + Zeroize>(Vec<(Id, Vec<(G::Scalar, G)>)>);
impl<Id: Copy, G: Group + Zeroize> Zeroize for BatchVerifier<Id, G>
where
  G::Scalar: Zeroize,
{
  fn zeroize(&mut self) {
    for (_, pairs) in self.0.iter_mut() {
      for pair in pairs.iter_mut() {
        pair.zeroize();
      }
    }
  }
}

fn weight<R: RngCore + CryptoRng, F: Field>(rng: &mut R, i: usize) -> F {
  if i == 0 {
    F::one()
  } else {
    let mut weight;
    while {
      // Generate a random scalar
      weight = F::random(&mut *rng);

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
  }
}

#[cfg(feature = "batch")]
impl<Id: Copy, G: Group + Zeroize> BatchVerifier<Id, G>
where
  <G as Group>::Scalar: PrimeFieldBits + Zeroize,
{
  pub fn new(capacity: usize) -> BatchVerifier<Id, G> {
    BatchVerifier(Vec::with_capacity(capacity))
  }

  pub fn queue<I: IntoIterator<Item = (G::Scalar, G)>>(&mut self, id: Id, pairs: I) {
    self.0.push((id, pairs.into_iter().collect()));
  }

  fn flat<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<(G::Scalar, G)> {
    self
      .0
      .iter()
      .enumerate()
      .flat_map(|(i, pairs)| {
        let weight: G::Scalar = weight(rng, i);
        pairs.1.iter().map(move |(f, g)| (*f * weight, *g))
      })
      .collect::<Vec<_>>()
  }

  #[must_use]
  pub fn verify_core<R: RngCore + CryptoRng>(&self, rng: &mut R) -> bool {
    let mut flat = self.flat(rng);
    let res = multiexp(&flat).is_identity().into();
    flat.zeroize();
    res
  }

  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(mut self, rng: &mut R) -> bool {
    let res = self.verify_core(rng);
    self.zeroize();
    res
  }

  #[must_use]
  pub fn verify_vartime<R: RngCore + CryptoRng>(&self, rng: &mut R) -> bool {
    multiexp_vartime(&self.flat(rng)).is_identity().into()
  }

  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Option<Id> {
    let mut slice = self.0.as_slice();
    while slice.len() > 1 {
      let split = slice.len() / 2;
      if BatchVerifier(slice[.. split].to_vec()).verify_vartime(rng) {
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

  pub fn verify_with_vartime_blame<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> Result<(), Id> {
    let res = if self.verify_core(rng) { Ok(()) } else { Err(self.blame_vartime(rng).unwrap()) };
    self.zeroize();
    res
  }

  pub fn verify_vartime_with_vartime_blame<R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
  ) -> Result<(), Id> {
    if self.verify_vartime(rng) {
      Ok(())
    } else {
      Err(self.blame_vartime(rng).unwrap())
    }
  }
}
