#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use ff::{Field, PrimeField};
use group::prime::PrimeGroup;

#[cfg(feature = "serialize")]
use std::io::{self, ErrorKind, Error, Read, Write};

#[cfg(feature = "experimental")]
pub mod cross_group;

#[cfg(test)]
mod tests;

pub(crate) fn challenge<T: Transcript, F: PrimeField>(transcript: &mut T) -> F {
  // From here, there are three ways to get a scalar under the ff/group API
  // 1: Scalar::random(ChaCha20Rng::from_seed(self.transcript.rng_seed(b"challenge")))
  // 2: Grabbing a UInt library to perform reduction by the modulus, then determining endianess
  //    and loading it in
  // 3: Iterating over each byte and manually doubling/adding. This is simplest

  // Get a wide amount of bytes to safely reduce without bias
  let target = ((usize::try_from(F::NUM_BITS).unwrap() + 7) / 8) * 2;
  let mut challenge_bytes = transcript.challenge(b"challenge").as_ref().to_vec();
  while challenge_bytes.len() < target {
    // Secure given transcripts updating on challenge
    challenge_bytes.extend(transcript.challenge(b"challenge_extension").as_ref());
  }
  challenge_bytes.truncate(target);

  let mut challenge = F::zero();
  for b in challenge_bytes {
    for _ in 0 .. 8 {
      challenge = challenge.double();
    }
    challenge += F::from(u64::from(b));
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

#[derive(Debug)]
pub enum DLEqError {
  InvalidProof,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DLEqProof<G: PrimeGroup> {
  c: G::Scalar,
  s: G::Scalar,
}

#[allow(non_snake_case)]
impl<G: PrimeGroup> DLEqProof<G> {
  fn transcript<T: Transcript>(transcript: &mut T, generator: G, nonce: G, point: G) {
    transcript.append_message(b"generator", generator.to_bytes().as_ref());
    transcript.append_message(b"nonce", nonce.to_bytes().as_ref());
    transcript.append_message(b"point", point.to_bytes().as_ref());
  }

  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: &[G],
    mut scalar: G::Scalar,
  ) -> DLEqProof<G>
  where
    G::Scalar: Zeroize,
  {
    let mut r = G::Scalar::random(rng);

    transcript.domain_separate(b"dleq");
    for generator in generators {
      Self::transcript(transcript, *generator, *generator * r, *generator * scalar);
    }

    let c = challenge(transcript);
    let s = r + (c * scalar);

    scalar.zeroize();
    r.zeroize();

    DLEqProof { c, s }
  }

  pub fn verify<T: Transcript>(
    &self,
    transcript: &mut T,
    generators: &[G],
    points: &[G],
  ) -> Result<(), DLEqError> {
    if generators.len() != points.len() {
      Err(DLEqError::InvalidProof)?;
    }

    transcript.domain_separate(b"dleq");
    for (generator, point) in generators.iter().zip(points) {
      Self::transcript(transcript, *generator, (*generator * self.s) - (*point * self.c), *point);
    }

    if self.c != challenge(transcript) {
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
