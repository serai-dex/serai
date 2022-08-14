#![cfg_attr(not(feature = "std"), no_std)]

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use curve::{
  ff::{Field, PrimeField},
  group::GroupEncoding,
  Curve,
};

#[cfg(feature = "serialize")]
use std::io::{self, Read, Write};
#[cfg(feature = "serialize")]
use curve::CurveError;

#[cfg(feature = "experimental")]
pub mod cross_group;

#[cfg(test)]
mod tests;

pub(crate) fn challenge<T: Transcript, C: Curve>(transcript: &mut T) -> C::F {
  // From here, there are three ways to get a scalar under the ff/group API
  // 1: Scalar::random(ChaCha12Rng::from_seed(self.transcript.rng_seed(b"challenge")))
  // 2: Grabbing a UInt library to perform reduction by the modulus, then determining endianess
  //    and loading it in
  // 3: Iterating over each byte and manually doubling/adding. This is simplest

  // Get a wide amount of bytes to safely reduce without bias
  let target = ((usize::try_from(C::F::NUM_BITS).unwrap() + 7) / 8) * 2;
  let mut challenge_bytes = transcript.challenge(b"challenge").as_ref().to_vec();
  while challenge_bytes.len() < target {
    // Secure given transcripts updating on challenge
    challenge_bytes.extend(transcript.challenge(b"challenge_extension").as_ref());
  }
  challenge_bytes.truncate(target);

  let mut challenge = C::F::zero();
  for b in challenge_bytes {
    for _ in 0 .. 8 {
      challenge = challenge.double();
    }
    challenge += C::F::from(u64::from(b));
  }
  challenge
}

#[derive(Debug)]
pub enum DLEqError {
  InvalidProof,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DLEqProof<C: Curve> {
  c: C::F,
  s: C::F,
}

#[allow(non_snake_case)]
impl<C: Curve> DLEqProof<C> {
  fn transcript<T: Transcript>(transcript: &mut T, generator: C::G, nonce: C::G, point: C::G) {
    transcript.append_message(b"generator", generator.to_bytes().as_ref());
    transcript.append_message(b"nonce", nonce.to_bytes().as_ref());
    transcript.append_message(b"point", point.to_bytes().as_ref());
  }

  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: &[C::G],
    mut scalar: C::F,
  ) -> DLEqProof<C> {
    let mut r = C::F::random(rng);

    transcript.domain_separate(b"dleq");
    for generator in generators {
      Self::transcript(transcript, *generator, *generator * r, *generator * scalar);
    }

    let c = challenge::<_, C>(transcript);
    let s = r + (c * scalar);

    scalar.zeroize();
    r.zeroize();

    DLEqProof { c, s }
  }

  pub fn verify<T: Transcript>(
    &self,
    transcript: &mut T,
    generators: &[C::G],
    points: &[C::G],
  ) -> Result<(), DLEqError> {
    if generators.len() != points.len() {
      Err(DLEqError::InvalidProof)?;
    }

    transcript.domain_separate(b"dleq");
    for (generator, point) in generators.iter().zip(points) {
      Self::transcript(transcript, *generator, (*generator * self.s) - (*point * self.c), *point);
    }

    if self.c != challenge::<_, C>(transcript) {
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
  pub fn deserialize<R: Read>(r: &mut R) -> Result<DLEqProof<C>, CurveError> {
    Ok(DLEqProof { c: C::read_F(r)?, s: C::read_F(r)? })
  }
}
