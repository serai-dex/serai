use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use ff::{Field, PrimeField};
use group::prime::PrimeGroup;

#[cfg(feature = "serialize")]
use std::io::{self, ErrorKind, Error, Read, Write};

#[cfg(feature = "cross_group")]
pub mod cross_group;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Generators<G: PrimeGroup> {
  primary: G,
  alt: G
}

impl<G: PrimeGroup> Generators<G> {
  pub fn new(primary: G, alt: G) -> Generators<G> {
    Generators { primary, alt }
  }

  fn transcript<T: Transcript>(&self, transcript: &mut T) {
    transcript.domain_separate(b"generators");
    transcript.append_message(b"primary", self.primary.to_bytes().as_ref());
    transcript.append_message(b"alternate", self.alt.to_bytes().as_ref());
  }
}

pub(crate) fn challenge<T: Transcript, F: PrimeField>(transcript: &mut T) -> F {
  assert!(F::NUM_BITS <= 384);

  // From here, there are three ways to get a scalar under the ff/group API
  // 1: Scalar::random(ChaCha12Rng::from_seed(self.transcript.rng_seed(b"challenge")))
  // 2: Grabbing a UInt library to perform reduction by the modulus, then determining endianess
  //    and loading it in
  // 3: Iterating over each byte and manually doubling/adding. This is simplest
  let challenge_bytes = transcript.challenge(b"challenge");
  assert!(challenge_bytes.as_ref().len() == 64);

  let mut challenge = F::zero();
  for b in challenge_bytes.as_ref() {
    for _ in 0 .. 8 {
      challenge = challenge.double();
    }
    challenge += F::from(u64::from(*b));
  }
  challenge
}

#[cfg(feature = "serialize")]
fn read_scalar<R: Read, F: PrimeField>(r: &mut R) -> io::Result<F> {
  let mut repr = F::Repr::default();
  r.read_exact(repr.as_mut())?;
  let scalar = F::from_repr(repr);
  if scalar.is_none().into() {
    Err(Error::new(ErrorKind::Other, "invalid scalar"))?;
  }
  Ok(scalar.unwrap())
}

#[derive(Error, Debug)]
pub enum DLEqError {
  #[error("invalid proof")]
  InvalidProof
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DLEqProof<G: PrimeGroup> {
  c: G::Scalar,
  s: G::Scalar
}

#[allow(non_snake_case)]
impl<G: PrimeGroup> DLEqProof<G> {
  fn challenge<T: Transcript>(
    transcript: &mut T,
    generators: Generators<G>,
    nonces: (G, G),
    points: (G, G)
  ) -> G::Scalar {
    generators.transcript(transcript);
    transcript.domain_separate(b"dleq");
    transcript.append_message(b"nonce_primary", nonces.0.to_bytes().as_ref());
    transcript.append_message(b"nonce_alternate", nonces.1.to_bytes().as_ref());
    transcript.append_message(b"point_primary", points.0.to_bytes().as_ref());
    transcript.append_message(b"point_alternate", points.1.to_bytes().as_ref());
    challenge(transcript)
  }

  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: Generators<G>,
    scalar: G::Scalar
  ) -> DLEqProof<G> {
    let r = G::Scalar::random(rng);
    let c = Self::challenge(
      transcript,
      generators,
      (generators.primary * r, generators.alt * r),
      (generators.primary * scalar, generators.alt * scalar)
    );
    let s = r + (c * scalar);

    DLEqProof { c, s }
  }

  pub fn verify<T: Transcript>(
    &self,
    transcript: &mut T,
    generators: Generators<G>,
    points: (G, G)
  ) -> Result<(), DLEqError> {
    if self.c != Self::challenge(
      transcript,
      generators,
      (
        (generators.primary * self.s) - (points.0 * self.c),
        (generators.alt * self.s) -  (points.1 * self.c)
      ),
      points
    ) {
      Err(DLEqError::InvalidProof)?;
    }

    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(self.c.to_repr().as_ref())?;
    w.write_all(self.s.to_repr().as_ref())
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> io::Result<DLEqProof<G>> {
    Ok(DLEqProof { c: read_scalar(r)?, s: read_scalar(r)? })
  }
}
