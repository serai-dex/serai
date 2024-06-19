#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

use core::ops::Deref;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use transcript::Transcript;

use ff::{Field, PrimeField};
use group::prime::PrimeGroup;

#[cfg(feature = "serialize")]
use std::io::{self, Error, Read, Write};

/// A cross-group DLEq proof capable of proving that two public keys, across two different curves,
/// share a private key.
#[cfg(feature = "experimental")]
pub mod cross_group;

#[cfg(test)]
mod tests;

// Produce a non-biased challenge from the transcript in the specified field
pub(crate) fn challenge<T: Transcript, F: PrimeField>(transcript: &mut T) -> F {
  // From here, there are three ways to get a scalar under the ff/group API
  // 1: Scalar::random(ChaCha20Rng::from_seed(self.transcript.rng_seed(b"challenge")))
  // 2: Grabbing a UInt library to perform reduction by the modulus, then determining endianness
  //    and loading it in
  // 3: Iterating over each byte and manually doubling/adding. This is simplest

  let mut challenge = F::ZERO;

  // Get a wide amount of bytes to safely reduce without bias
  // In most cases, <=1.5x bytes is enough. 2x is still standard and there's some theoretical
  // groups which may technically require more than 1.5x bytes for this to work as intended
  let target_bytes = ((usize::try_from(F::NUM_BITS).unwrap() + 7) / 8) * 2;
  let mut challenge_bytes = transcript.challenge(b"challenge");
  let challenge_bytes_len = challenge_bytes.as_ref().len();
  // If the challenge is 32 bytes, and we need 64, we need two challenges
  let needed_challenges = (target_bytes + (challenge_bytes_len - 1)) / challenge_bytes_len;

  // The following algorithm should be equivalent to a wide reduction of the challenges,
  // interpreted as concatenated, big-endian byte string
  let mut handled_bytes = 0;
  'outer: for _ in 0 ..= needed_challenges {
    // Cursor of which byte of the challenge to use next
    let mut b = 0;
    while b < challenge_bytes_len {
      // Get the next amount of bytes to attempt
      // Only grabs the needed amount of bytes, up to 8 at a time (u64), so long as they're
      // available in the challenge
      let chunk_bytes = (target_bytes - handled_bytes).min(8).min(challenge_bytes_len - b);

      let mut chunk = 0;
      for _ in 0 .. chunk_bytes {
        chunk <<= 8;
        chunk |= u64::from(challenge_bytes.as_ref()[b]);
        b += 1;
      }
      // Add this chunk
      challenge += F::from(chunk);

      handled_bytes += chunk_bytes;
      // If we've reached the target amount of bytes, break
      if handled_bytes == target_bytes {
        break 'outer;
      }

      // Shift over by however many bits will be in the next chunk
      let next_chunk_bytes = (target_bytes - handled_bytes).min(8).min(challenge_bytes_len);
      for _ in 0 .. (next_chunk_bytes * 8) {
        challenge = challenge.double();
      }
    }

    // Secure thanks to the Transcript trait having a bound of updating on challenge
    challenge_bytes = transcript.challenge(b"challenge_extension");
  }

  challenge
}

// Helper function to read a scalar
#[cfg(feature = "serialize")]
fn read_scalar<R: Read, F: PrimeField>(r: &mut R) -> io::Result<F> {
  let mut repr = F::Repr::default();
  r.read_exact(repr.as_mut())?;
  let scalar = F::from_repr(repr);
  if scalar.is_none().into() {
    Err(Error::other("invalid scalar"))?;
  }
  Ok(scalar.unwrap())
}

/// Error for DLEq proofs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DLEqError {
  /// The proof was invalid.
  InvalidProof,
}

/// A proof that points have the same discrete logarithm across generators.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct DLEqProof<G: PrimeGroup<Scalar: Zeroize>> {
  c: G::Scalar,
  s: G::Scalar,
}

#[allow(non_snake_case)]
impl<G: PrimeGroup<Scalar: Zeroize>> DLEqProof<G> {
  fn transcript<T: Transcript>(transcript: &mut T, generator: G, nonce: G, point: G) {
    transcript.append_message(b"generator", generator.to_bytes());
    transcript.append_message(b"nonce", nonce.to_bytes());
    transcript.append_message(b"point", point.to_bytes());
  }

  /// Prove that the points created by `scalar * G`, for each specified generator, share a discrete
  /// logarithm.
  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: &[G],
    scalar: &Zeroizing<G::Scalar>,
  ) -> DLEqProof<G> {
    let r = Zeroizing::new(G::Scalar::random(rng));

    transcript.domain_separate(b"dleq");
    for generator in generators {
      // R, A
      Self::transcript(transcript, *generator, *generator * r.deref(), *generator * scalar.deref());
    }

    let c = challenge(transcript);
    // r + ca
    let s = (c * scalar.deref()) + r.deref();

    DLEqProof { c, s }
  }

  // Transcript a specific generator/nonce/point (G/R/A), as used when verifying a proof.
  // This takes in the generator/point, and then the challenge and solution to calculate the nonce.
  fn verify_statement<T: Transcript>(
    transcript: &mut T,
    generator: G,
    point: G,
    c: G::Scalar,
    s: G::Scalar,
  ) {
    // s = r + ca
    // sG - cA = R
    // R, A
    Self::transcript(transcript, generator, (generator * s) - (point * c), point);
  }

  /// Verify the specified points share a discrete logarithm across the specified generators.
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
      Self::verify_statement(transcript, *generator, *point, self.c, self.s);
    }

    if self.c != challenge(transcript) {
      Err(DLEqError::InvalidProof)?;
    }

    Ok(())
  }

  /// Write a DLEq proof to something implementing Write.
  #[cfg(feature = "serialize")]
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(self.c.to_repr().as_ref())?;
    w.write_all(self.s.to_repr().as_ref())
  }

  /// Read a DLEq proof from something implementing Read.
  #[cfg(feature = "serialize")]
  pub fn read<R: Read>(r: &mut R) -> io::Result<DLEqProof<G>> {
    Ok(DLEqProof { c: read_scalar(r)?, s: read_scalar(r)? })
  }

  /// Serialize a DLEq proof to a `Vec<u8>`.
  #[cfg(feature = "serialize")]
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }
}

/// A proof that multiple series of points each have a single discrete logarithm across generators.
///
/// This is effectively n distinct DLEq proofs, one for each discrete logarithm and its points
/// across some generators, yet with a smaller overall proof size.
#[cfg(feature = "std")]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct MultiDLEqProof<G: PrimeGroup<Scalar: Zeroize>> {
  c: G::Scalar,
  s: Vec<G::Scalar>,
}

#[cfg(feature = "std")]
#[allow(non_snake_case)]
impl<G: PrimeGroup<Scalar: Zeroize>> MultiDLEqProof<G> {
  /// Prove for each scalar that the series of points created by multiplying it against its
  /// matching generators share a discrete logarithm.
  /// This function panics if `generators.len() != scalars.len()`.
  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: &[Vec<G>],
    scalars: &[Zeroizing<G::Scalar>],
  ) -> MultiDLEqProof<G> {
    assert_eq!(
      generators.len(),
      scalars.len(),
      "amount of series of generators doesn't match the amount of scalars"
    );

    transcript.domain_separate(b"multi_dleq");

    let mut nonces = vec![];
    for (i, (scalar, generators)) in scalars.iter().zip(generators).enumerate() {
      // Delineate between discrete logarithms
      transcript.append_message(b"discrete_logarithm", i.to_le_bytes());

      let nonce = Zeroizing::new(G::Scalar::random(&mut *rng));
      for generator in generators {
        DLEqProof::transcript(
          transcript,
          *generator,
          *generator * nonce.deref(),
          *generator * scalar.deref(),
        );
      }
      nonces.push(nonce);
    }

    let c = challenge(transcript);

    let mut s = vec![];
    for (scalar, nonce) in scalars.iter().zip(nonces) {
      s.push((c * scalar.deref()) + nonce.deref());
    }

    MultiDLEqProof { c, s }
  }

  /// Verify each series of points share a discrete logarithm against their matching series of
  /// generators.
  pub fn verify<T: Transcript>(
    &self,
    transcript: &mut T,
    generators: &[Vec<G>],
    points: &[Vec<G>],
  ) -> Result<(), DLEqError> {
    if points.len() != generators.len() {
      Err(DLEqError::InvalidProof)?;
    }
    if self.s.len() != generators.len() {
      Err(DLEqError::InvalidProof)?;
    }

    transcript.domain_separate(b"multi_dleq");
    for (i, (generators, points)) in generators.iter().zip(points).enumerate() {
      if points.len() != generators.len() {
        Err(DLEqError::InvalidProof)?;
      }

      transcript.append_message(b"discrete_logarithm", i.to_le_bytes());
      for (generator, point) in generators.iter().zip(points) {
        DLEqProof::verify_statement(transcript, *generator, *point, self.c, self.s[i]);
      }
    }

    if self.c != challenge(transcript) {
      Err(DLEqError::InvalidProof)?;
    }

    Ok(())
  }

  /// Write a multi-DLEq proof to something implementing Write.
  #[cfg(feature = "serialize")]
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(self.c.to_repr().as_ref())?;
    for s in &self.s {
      w.write_all(s.to_repr().as_ref())?;
    }
    Ok(())
  }

  /// Read a multi-DLEq proof from something implementing Read.
  #[cfg(feature = "serialize")]
  pub fn read<R: Read>(r: &mut R, discrete_logs: usize) -> io::Result<MultiDLEqProof<G>> {
    let c = read_scalar(r)?;
    let mut s = vec![];
    for _ in 0 .. discrete_logs {
      s.push(read_scalar(r)?);
    }
    Ok(MultiDLEqProof { c, s })
  }

  /// Serialize a multi-DLEq proof to a `Vec<u8>`.
  #[cfg(feature = "serialize")]
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }
}
