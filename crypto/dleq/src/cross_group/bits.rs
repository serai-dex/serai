use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use group::{ff::PrimeFieldBits, prime::PrimeGroup};

use crate::{Generators, cross_group::DLEqError};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use crate::cross_group::read_point;

pub trait RingSignature<G0: PrimeGroup, G1: PrimeGroup>: Sized {
  type Context;

  const LEN: usize;

  fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    ring: &[(G0, G1)],
    actual: usize,
    blinding_key: (G0::Scalar, G1::Scalar)
  ) -> Self;

  fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    context: &mut Self::Context,
    ring: &[(G0, G1)]
  ) -> Result<(), DLEqError>;

  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Self>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Bits<G0: PrimeGroup, G1: PrimeGroup, RING: RingSignature<G0, G1>> {
  pub(crate) commitments: (G0, G1),
  signature: RING
}

impl<G0: PrimeGroup, G1: PrimeGroup, RING: RingSignature<G0, G1>> Bits<G0, G1, RING>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  fn transcript<T: Transcript>(transcript: &mut T, i: usize, commitments: (G0, G1)) {
    if i == 0 {
      transcript.domain_separate(b"cross_group_dleq");
    }
    transcript.append_message(b"bit_group", &u16::try_from(i).unwrap().to_le_bytes());
    transcript.append_message(b"commitment_0", commitments.0.to_bytes().as_ref());
    transcript.append_message(b"commitment_1", commitments.1.to_bytes().as_ref());
  }

  fn ring(pow_2: (G0, G1), commitments: (G0, G1)) -> Vec<(G0, G1)> {
    let mut res = vec![(G0::identity(), G1::identity()); RING::LEN];
    res[RING::LEN - 1] = commitments;
    for i in (0 .. (RING::LEN - 1)).rev() {
      res[i] = (res[i + 1].0 - pow_2.0, res[i + 1].1 - pow_2.1);
    }
    res
  }

  fn shift(pow_2: &mut (G0, G1)) {
    pow_2.0 = pow_2.0.double();
    pow_2.1 = pow_2.1.double();
    if RING::LEN == 4 {
      pow_2.0 = pow_2.0.double();
      pow_2.1 = pow_2.1.double();
    }
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    i: usize,
    pow_2: &mut (G0, G1),
    bits: u8,
    blinding_key: (G0::Scalar, G1::Scalar)
  ) -> Self {
    debug_assert!((RING::LEN == 2) || (RING::LEN == 4));

    let mut commitments = (
      (generators.0.alt * blinding_key.0),
      (generators.1.alt * blinding_key.1)
    );
    commitments.0 += pow_2.0 * G0::Scalar::from(bits.into());
    commitments.1 += pow_2.1 * G1::Scalar::from(bits.into());
    Self::transcript(transcript, i, commitments);

    let ring = Self::ring(*pow_2, commitments);
    // Invert the index to get the raw blinding key's position in the ring
    let actual = RING::LEN - 1 - usize::from(bits);
    let signature = RING::prove(rng, transcript.clone(), generators, &ring, actual, blinding_key);

    Self::shift(pow_2);
    Bits { commitments, signature }
  }

  pub(crate) fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    context: &mut RING::Context,
    i: usize,
    pow_2: &mut (G0, G1)
  ) -> Result<(), DLEqError> {
    debug_assert!((RING::LEN == 2) || (RING::LEN == 4));

    Self::transcript(transcript, i, self.commitments);
    self.signature.verify(
      rng,
      transcript.clone(),
      generators,
      context,
      &Self::ring(*pow_2, self.commitments)
    )?;

    Self::shift(pow_2);
    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub(crate) fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.commitments.0.to_bytes().as_ref())?;
    w.write_all(self.commitments.1.to_bytes().as_ref())?;
    self.signature.serialize(w)
  }

  #[cfg(feature = "serialize")]
  pub(crate) fn deserialize<Re: Read>(r: &mut Re) -> std::io::Result<Self> {
    Ok(Bits { commitments: (read_point(r)?, read_point(r)?), signature: RING::deserialize(r)? })
  }
}
