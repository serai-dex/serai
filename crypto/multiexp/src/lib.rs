use group::{ff::PrimeField, Group};

#[cfg(feature = "batch")]
use group::ff::Field;
#[cfg(feature = "batch")]
use rand_core::{RngCore, CryptoRng};

fn prep<
  G: Group,
  I: IntoIterator<Item = (G::Scalar, G)>
>(pairs: I, little: bool) -> (Vec<Vec<u8>>, Vec<[G; 16]>) {
  let mut nibbles = vec![];
  let mut tables = vec![];
  for pair in pairs.into_iter() {
    let p = nibbles.len();
    nibbles.push(vec![]);
    {
      let mut repr = pair.0.to_repr();
      let bytes = repr.as_mut();
      if !little {
        bytes.reverse();
      }

      nibbles[p].resize(bytes.len() * 2, 0);
      for i in 0 .. bytes.len() {
        nibbles[p][i * 2] = bytes[i] & 0b1111;
        nibbles[p][(i * 2) + 1] = (bytes[i] >> 4) & 0b1111;
      }
    }

    tables.push([G::identity(); 16]);
    let mut accum = G::identity();
    for i in 1 .. 16 {
      accum += pair.1;
      tables[p][i] = accum;
    }
  }

  (nibbles, tables)
}

// An implementation of Straus, with a extremely minimal API that lets us add other algorithms in
// the future. Takes in an iterator of scalars and points with a boolean for if the scalars are
// little endian encoded in their Reprs or not
pub fn multiexp<
  G: Group,
  I: IntoIterator<Item = (G::Scalar, G)>
>(pairs: I, little: bool) -> G {
  let (nibbles, tables) = prep(pairs, little);

  let mut res = G::identity();
  for b in (0 .. nibbles[0].len()).rev() {
    for _ in 0 .. 4 {
      res = res.double();
    }

    for s in 0 .. tables.len() {
      res += tables[s][usize::from(nibbles[s][b])];
    }
  }
  res
}

pub fn multiexp_vartime<
  G: Group,
  I: IntoIterator<Item = (G::Scalar, G)>
>(pairs: I, little: bool) -> G {
  let (nibbles, tables) = prep(pairs, little);

  let mut res = G::identity();
  for b in (0 .. nibbles[0].len()).rev() {
    for _ in 0 .. 4 {
      res = res.double();
    }

    for s in 0 .. tables.len() {
      if nibbles[s][b] != 0 {
        res += tables[s][usize::from(nibbles[s][b])];
      }
    }
  }
  res
}

#[cfg(feature = "batch")]
pub struct BatchVerifier<Id: Copy, G: Group>(Vec<(Id, Vec<(G::Scalar, G)>)>, bool);

#[cfg(feature = "batch")]
impl<Id: Copy, G: Group> BatchVerifier<Id, G> {
  pub fn new(capacity: usize, endian: bool) -> BatchVerifier<Id, G> {
    BatchVerifier(Vec::with_capacity(capacity), endian)
  }

  pub fn queue<
    R: RngCore + CryptoRng,
    I: IntoIterator<Item = (G::Scalar, G)>
  >(&mut self, rng: &mut R, id: Id, pairs: I) {
    // Define a unique scalar factor for this set of variables so individual items can't overlap
    let u = if self.0.len() == 0 {
      G::Scalar::one()
    } else {
      G::Scalar::random(rng)
    };
    self.0.push((id, pairs.into_iter().map(|(scalar, point)| (scalar * u, point)).collect()));
  }

  pub fn verify(&self) -> bool {
    multiexp(
      self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned(),
      self.1
    ).is_identity().into()
  }

  pub fn verify_vartime(&self) -> bool {
    multiexp_vartime(
      self.0.iter().flat_map(|pairs| pairs.1.iter()).cloned(),
      self.1
    ).is_identity().into()
  }

  // A constant time variant may be beneficial for robust protocols
  pub fn blame_vartime(&self) -> Option<Id> {
    let mut slice = self.0.as_slice();
    while slice.len() > 1 {
      let split = slice.len() / 2;
      if multiexp_vartime(
        slice[.. split].iter().flat_map(|pairs| pairs.1.iter()).cloned(),
        self.1
      ).is_identity().into() {
        slice = &slice[split ..];
      } else {
        slice = &slice[.. split];
      }
    }

    slice.get(0).filter(
      |(_, value)| !bool::from(multiexp_vartime(value.clone(), self.1).is_identity())
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
