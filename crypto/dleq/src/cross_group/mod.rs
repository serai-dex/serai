use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use group::{ff::{PrimeField, PrimeFieldBits}, prime::PrimeGroup};

use crate::Generators;

pub mod scalar;

pub(crate) mod schnorr;
use schnorr::SchnorrPoK;

mod bits;
use bits::{RingSignature, Bits};

pub mod linear;

#[cfg(feature = "serialize")]
use std::io::Read;

#[cfg(feature = "serialize")]
pub(crate) fn read_point<R: Read, G: PrimeGroup>(r: &mut R) -> std::io::Result<G> {
  let mut repr = G::Repr::default();
  r.read_exact(repr.as_mut())?;
  let point = G::from_bytes(&repr);
  if point.is_none().into() {
    Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid point"))?;
  }
  Ok(point.unwrap())
}

#[derive(Error, PartialEq, Eq, Debug)]
pub enum DLEqError {
  #[error("invalid proof of knowledge")]
  InvalidProofOfKnowledge,
  #[error("invalid proof length")]
  InvalidProofLength,
  #[error("invalid challenge")]
  InvalidChallenge,
  #[error("invalid proof")]
  InvalidProof
}

// Debug would be such a dump of data this likely isn't helpful, but at least it's available to
// anyone who wants it
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DLEqProof<
  G0: PrimeGroup,
  G1: PrimeGroup,
  RING: RingSignature<G0, G1>,
  REM: RingSignature<G0, G1>
> where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  bits: Vec<Bits<G0, G1, RING>>,
  remainder: Option<Bits<G0, G1, REM>>,
  poks: (SchnorrPoK<G0>, SchnorrPoK<G1>)
}

impl<
  G0: PrimeGroup,
  G1: PrimeGroup,
  RING: RingSignature<G0, G1>,
  REM: RingSignature<G0, G1>
> DLEqProof<G0, G1, RING, REM> where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  pub(crate) fn initialize_transcript<T: Transcript>(
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    keys: (G0, G1)
  ) {
    generators.0.transcript(transcript);
    generators.1.transcript(transcript);
    transcript.domain_separate(b"points");
    transcript.append_message(b"point_0", keys.0.to_bytes().as_ref());
    transcript.append_message(b"point_1", keys.1.to_bytes().as_ref());
  }

  pub(crate) fn blinding_key<R: RngCore + CryptoRng, F: PrimeField>(
    rng: &mut R,
    total: &mut F,
    last: bool
  ) -> F {
    let blinding_key = if last {
      -*total
    } else {
      F::random(&mut *rng)
    };
    *total += blinding_key;
    blinding_key
  }

  fn reconstruct_keys(&self) -> (G0, G1) {
    let mut res = (
      self.bits.iter().map(|bit| bit.commitments.0).sum::<G0>(),
      self.bits.iter().map(|bit| bit.commitments.1).sum::<G1>()
    );

    if let Some(bit) = &self.remainder {
      res.0 += bit.commitments.0;
      res.1 += bit.commitments.1;
    }

    res
  }
}
