use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use group::{ff::PrimeFieldBits, prime::PrimeGroup};
use multiexp::BatchVerifier;

use crate::cross_group::{
  Generators, DLEqError,
  aos::{Re, Aos},
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use crate::cross_group::read_point;

#[allow(clippy::enum_variant_names)]
pub(crate) enum BitSignature {
  ClassicLinear,
  ConciseLinear,
  EfficientLinear,
  CompromiseLinear,
}

impl BitSignature {
  pub(crate) const fn to_u8(&self) -> u8 {
    match self {
      BitSignature::ClassicLinear => 0,
      BitSignature::ConciseLinear => 1,
      BitSignature::EfficientLinear => 2,
      BitSignature::CompromiseLinear => 3,
    }
  }

  pub(crate) const fn from(algorithm: u8) -> BitSignature {
    match algorithm {
      0 => BitSignature::ClassicLinear,
      1 => BitSignature::ConciseLinear,
      2 => BitSignature::EfficientLinear,
      3 => BitSignature::CompromiseLinear,
      _ => panic!("Unknown algorithm"),
    }
  }

  pub(crate) const fn bits(&self) -> u8 {
    match self {
      BitSignature::ClassicLinear | BitSignature::EfficientLinear => 1,
      BitSignature::ConciseLinear | BitSignature::CompromiseLinear => 2,
    }
  }

  pub(crate) const fn ring_len(&self) -> usize {
    2_usize.pow(self.bits() as u32)
  }

  fn aos_form<G0: PrimeGroup, G1: PrimeGroup>(&self) -> Re<G0, G1> {
    match self {
      BitSignature::ClassicLinear | BitSignature::ConciseLinear => Re::e_default(),
      BitSignature::EfficientLinear | BitSignature::CompromiseLinear => Re::R_default(),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Bits<
  G0: PrimeGroup + Zeroize,
  G1: PrimeGroup + Zeroize,
  const SIGNATURE: u8,
  const RING_LEN: usize,
> {
  pub(crate) commitments: (G0, G1),
  signature: Aos<G0, G1, RING_LEN>,
}

impl<
    G0: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    G1: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    const SIGNATURE: u8,
    const RING_LEN: usize,
  > Bits<G0, G1, SIGNATURE, RING_LEN>
{
  fn transcript<T: Transcript>(transcript: &mut T, i: usize, commitments: (G0, G1)) {
    transcript.domain_separate(b"bits");
    transcript.append_message(b"group", u16::try_from(i).unwrap().to_le_bytes());
    transcript.append_message(b"commitment_0", commitments.0.to_bytes());
    transcript.append_message(b"commitment_1", commitments.1.to_bytes());
  }

  fn ring(pow_2: (G0, G1), commitments: (G0, G1)) -> Vec<(G0, G1)> {
    let mut res = vec![commitments; RING_LEN];
    for i in 1 .. RING_LEN {
      res[i] = (res[i - 1].0 - pow_2.0, res[i - 1].1 - pow_2.1);
    }
    res
  }

  fn shift(pow_2: &mut (G0, G1)) {
    for _ in 0 .. BitSignature::from(SIGNATURE).bits() {
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
    mut bits: u8,
    blinding_key: &mut (G0::Scalar, G1::Scalar),
  ) -> Self {
    let mut commitments =
      ((generators.0.alt * blinding_key.0), (generators.1.alt * blinding_key.1));
    commitments.0 += pow_2.0 * G0::Scalar::from(bits.into());
    commitments.1 += pow_2.1 * G1::Scalar::from(bits.into());

    Self::transcript(transcript, i, commitments);

    let signature = Aos::prove(
      rng,
      transcript,
      generators,
      &Self::ring(*pow_2, commitments),
      usize::from(bits),
      blinding_key,
      BitSignature::from(SIGNATURE).aos_form(),
    );
    bits.zeroize();

    Self::shift(pow_2);
    Bits { commitments, signature }
  }

  pub(crate) fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    batch: &mut (BatchVerifier<(), G0>, BatchVerifier<(), G1>),
    i: usize,
    pow_2: &mut (G0, G1),
  ) -> Result<(), DLEqError> {
    Self::transcript(transcript, i, self.commitments);

    self.signature.verify(
      rng,
      transcript,
      generators,
      batch,
      &Self::ring(*pow_2, self.commitments),
    )?;

    Self::shift(pow_2);
    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub(crate) fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.commitments.0.to_bytes().as_ref())?;
    w.write_all(self.commitments.1.to_bytes().as_ref())?;
    self.signature.write(w)
  }

  #[cfg(feature = "serialize")]
  pub(crate) fn read<R: Read>(r: &mut R) -> std::io::Result<Self> {
    Ok(Bits {
      commitments: (read_point(r)?, read_point(r)?),
      signature: Aos::read(r, BitSignature::from(SIGNATURE).aos_form())?,
    })
  }
}
