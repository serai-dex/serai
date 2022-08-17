use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use curve::{
  group::{Group, GroupEncoding},
  Curve, CurveError,
};
use multiexp::BatchVerifier;

use crate::cross_group::{
  Generators, DLEqError,
  aos::{Re, Aos},
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};

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

  pub(crate) const fn bits(&self) -> usize {
    match self {
      BitSignature::ClassicLinear => 1,
      BitSignature::ConciseLinear => 2,
      BitSignature::EfficientLinear => 1,
      BitSignature::CompromiseLinear => 2,
    }
  }

  pub(crate) const fn ring_len(&self) -> usize {
    2_usize.pow(self.bits() as u32)
  }

  fn aos_form<C0: Curve, C1: Curve>(&self) -> Re<C0, C1> {
    match self {
      BitSignature::ClassicLinear => Re::e_default(),
      BitSignature::ConciseLinear => Re::e_default(),
      BitSignature::EfficientLinear => Re::R_default(),
      BitSignature::CompromiseLinear => Re::R_default(),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Bits<C0: Curve, C1: Curve, const SIGNATURE: u8, const RING_LEN: usize> {
  pub(crate) commitments: (C0::G, C1::G),
  signature: Aos<C0, C1, RING_LEN>,
}

impl<C0: Curve, C1: Curve, const SIGNATURE: u8, const RING_LEN: usize>
  Bits<C0, C1, SIGNATURE, RING_LEN>
{
  fn transcript<T: Transcript>(transcript: &mut T, i: usize, commitments: (C0::G, C1::G)) {
    transcript.domain_separate(b"bits");
    transcript.append_message(b"group", &u16::try_from(i).unwrap().to_le_bytes());
    transcript.append_message(b"commitment_0", commitments.0.to_bytes().as_ref());
    transcript.append_message(b"commitment_1", commitments.1.to_bytes().as_ref());
  }

  fn ring(pow_2: (C0::G, C1::G), commitments: (C0::G, C1::G)) -> Vec<(C0::G, C1::G)> {
    let mut res = vec![commitments; RING_LEN];
    for i in 1 .. RING_LEN {
      res[i] = (res[i - 1].0 - pow_2.0, res[i - 1].1 - pow_2.1);
    }
    res
  }

  fn shift(pow_2: &mut (C0::G, C1::G)) {
    for _ in 0 .. BitSignature::from(SIGNATURE).bits() {
      pow_2.0 = pow_2.0.double();
      pow_2.1 = pow_2.1.double();
    }
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<C0::G>, Generators<C1::G>),
    i: usize,
    pow_2: &mut (C0::G, C1::G),
    mut bits: u8,
    blinding_key: &mut (C0::F, C1::F),
  ) -> Self {
    let mut commitments =
      ((generators.0.alt * blinding_key.0), (generators.1.alt * blinding_key.1));
    commitments.0 += pow_2.0 * C0::F::from(bits.into());
    commitments.1 += pow_2.1 * C1::F::from(bits.into());

    Self::transcript(transcript, i, commitments);

    let signature = Aos::prove(
      rng,
      transcript.clone(),
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

  pub(crate) fn verify<T: Clone + Transcript>(
    &self,
    transcript: &mut T,
    generators: (Generators<C0::G>, Generators<C1::G>),
    batch: &mut (BatchVerifier<(), C0::G>, BatchVerifier<(), C1::G>),
    i: usize,
    pow_2: &mut (C0::G, C1::G),
  ) -> Result<(), DLEqError> {
    Self::transcript(transcript, i, self.commitments);

    self.signature.verify(
      transcript.clone(),
      generators,
      batch,
      &Self::ring(*pow_2, self.commitments),
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
  pub(crate) fn deserialize<R: Read>(r: &mut R) -> Result<Self, CurveError> {
    Ok(Bits {
      commitments: (C0::G::read_G(r)?, C1::G::read_G(r)?),
      signature: Aos::deserialize(r, BitSignature::from(SIGNATURE).aos_form())?,
    })
  }
}
