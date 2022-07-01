use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use subtle::{Choice, ConditionallySelectable};

use transcript::Transcript;

use group::{ff::{Field, PrimeField, PrimeFieldBits}, prime::PrimeGroup};

use crate::{Generators, challenge};

pub mod scalar;
use scalar::{scalar_normalize, scalar_convert};

pub(crate) mod schnorr;
use schnorr::SchnorrPoK;

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use crate::read_scalar;

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bit<G0: PrimeGroup, G1: PrimeGroup> {
  commitments: (G0, G1),
  e: G0::Scalar,
  s: [(G0::Scalar, G1::Scalar); 2]
}

impl<G0: PrimeGroup, G1: PrimeGroup> Bit<G0, G1> {
  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.commitments.0.to_bytes().as_ref())?;
    w.write_all(self.commitments.1.to_bytes().as_ref())?;
    w.write_all(self.e.to_repr().as_ref())?;
    for i in 0 .. 2 {
      w.write_all(self.s[i].0.to_repr().as_ref())?;
      w.write_all(self.s[i].1.to_repr().as_ref())?;
    }
    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Bit<G0, G1>> {
    Ok(
      Bit {
        commitments: (read_point(r)?, read_point(r)?),
        e: read_scalar(r)?,
        s: [
          (read_scalar(r)?, read_scalar(r)?),
          (read_scalar(r)?, read_scalar(r)?)
        ]
      }
    )
  }
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
pub struct DLEqProof<G0: PrimeGroup, G1: PrimeGroup> {
  bits: Vec<Bit<G0, G1>>,
  poks: (SchnorrPoK<G0>, SchnorrPoK<G1>)
}

impl<G0: PrimeGroup, G1: PrimeGroup> DLEqProof<G0, G1>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  fn initialize_transcript<T: Transcript>(
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

  fn blinding_key<R: RngCore + CryptoRng, F: PrimeField>(
    rng: &mut R,
    total: &mut F,
    pow_2: &mut F,
    last: bool
  ) -> F {
    let blinding_key = if last {
      -*total * pow_2.invert().unwrap()
    } else {
      F::random(&mut *rng)
    };
    *total += blinding_key * *pow_2;
    *pow_2 = pow_2.double();
    blinding_key
  }

  #[allow(non_snake_case)]
  fn nonces<T: Transcript>(mut transcript: T, nonces: (G0, G1)) -> (G0::Scalar, G1::Scalar) {
    transcript.append_message(b"nonce_0", nonces.0.to_bytes().as_ref());
    transcript.append_message(b"nonce_1", nonces.1.to_bytes().as_ref());
    scalar_normalize(challenge(&mut transcript))
  }

  #[allow(non_snake_case)]
  fn R_nonces<T: Transcript>(
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar)
  ) -> (G0::Scalar, G1::Scalar) {
    Self::nonces(
      transcript,
      (((generators.0.alt * s.0) - (A.0 * e.0)), ((generators.1.alt * s.1) - (A.1 * e.1)))
    )
  }

  fn reconstruct_key<G: PrimeGroup>(
    commitments: impl Iterator<Item = G>
  ) -> G where G::Scalar: PrimeFieldBits {
    let mut pow_2 = G::Scalar::one();
    multiexp::multiexp_vartime(
      &commitments.map(|commitment| {
        let res = (pow_2, commitment);
        pow_2 = pow_2.double();
        res
      }).collect::<Vec<_>>()
    )
  }

  fn reconstruct_keys(&self) -> (G0, G1) {
    (
      Self::reconstruct_key(self.bits.iter().map(|bit| bit.commitments.0)),
      Self::reconstruct_key(self.bits.iter().map(|bit| bit.commitments.1))
    )
  }

  fn transcript_bit<T: Transcript>(transcript: &mut T, i: usize, commitments: (G0, G1)) {
    if i == 0 {
      transcript.domain_separate(b"cross_group_dleq");
    }
    transcript.append_message(b"bit", &u16::try_from(i).unwrap().to_le_bytes());
    transcript.append_message(b"commitment_0", commitments.0.to_bytes().as_ref());
    transcript.append_message(b"commitment_1", commitments.1.to_bytes().as_ref());
  }

  /// Prove the cross-Group Discrete Log Equality for the points derived from the provided Scalar.
  /// Since DLEq is proven for the same Scalar in both fields, and the provided Scalar may not be
  /// valid in the other Scalar field, the Scalar is normalized as needed and the normalized forms
  /// are returned. These are the actually equal discrete logarithms. The passed in Scalar is
  /// solely to enable various forms of Scalar generation, such as deterministic schemes
  pub fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    f: G0::Scalar
  ) -> (Self, (G0::Scalar, G1::Scalar)) {
    // At least one bit will be dropped from either field element, making it irrelevant which one
    // we get a random element in
    let f = scalar_normalize::<_, G1::Scalar>(f);

    Self::initialize_transcript(
      transcript,
      generators,
      ((generators.0.primary * f.0), (generators.1.primary * f.1))
    );

    let poks = (
      SchnorrPoK::<G0>::prove(rng, transcript, generators.0.primary, f.0),
      SchnorrPoK::<G1>::prove(rng, transcript, generators.1.primary, f.1)
    );

    let mut blinding_key_total = (G0::Scalar::zero(), G1::Scalar::zero());
    let mut pow_2 = (G0::Scalar::one(), G1::Scalar::one());

    let raw_bits = f.0.to_le_bits();
    let capacity = usize::try_from(G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY)).unwrap();
    let mut bits = Vec::with_capacity(capacity);
    for (i, bit) in raw_bits.iter().enumerate() {
      let bit = *bit as u8;
      debug_assert_eq!(bit | 1, 1);

      let last = i == (capacity - 1);
      let blinding_key = (
        Self::blinding_key(&mut *rng, &mut blinding_key_total.0, &mut pow_2.0, last),
        Self::blinding_key(&mut *rng, &mut blinding_key_total.1, &mut pow_2.1, last)
      );
      if last {
        debug_assert_eq!(blinding_key_total.0, G0::Scalar::zero());
        debug_assert_eq!(blinding_key_total.1, G1::Scalar::zero());
      }

      let mut commitments = (
        (generators.0.alt * blinding_key.0),
        (generators.1.alt * blinding_key.1)
      );
      commitments.0 += generators.0.primary * G0::Scalar::from(bit.into());
      commitments.1 += generators.1.primary * G1::Scalar::from(bit.into());
      Self::transcript_bit(transcript, i, commitments);

      let nonces = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      let e_0 = Self::nonces(
        transcript.clone(),
        ((generators.0.alt * nonces.0), (generators.1.alt * nonces.1))
      );
      let mut s_0 = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));

      let mut to_sign = commitments;
      let bit = Choice::from(bit);
      let inv_bit = (!bit).unwrap_u8();
      to_sign.0 -= generators.0.primary * G0::Scalar::from(inv_bit.into());
      to_sign.1 -= generators.1.primary * G1::Scalar::from(inv_bit.into());
      let e_1 = Self::R_nonces(transcript.clone(), generators, (s_0.0, s_0.1), to_sign, e_0);
      let mut s_1 = (nonces.0 + (e_1.0 * blinding_key.0), nonces.1 + (e_1.1 * blinding_key.1));

      let e = G0::Scalar::conditional_select(&e_1.0, &e_0.0, bit);
      G0::Scalar::conditional_swap(&mut s_1.0, &mut s_0.0, bit);
      G1::Scalar::conditional_swap(&mut s_1.1, &mut s_0.1, bit);
      bits.push(Bit { commitments, e, s: [s_0, s_1] });

      // Break in order to not generate commitments for unused bits
      if last {
        break;
      }
    }

    let proof = DLEqProof { bits, poks };
    debug_assert_eq!(
      proof.reconstruct_keys(),
      (generators.0.primary * f.0, generators.1.primary * f.1)
    );
    (proof, f)
  }

  /// Verify a cross-Group Discrete Log Equality statement, returning the points proven for
  pub fn verify<T: Clone + Transcript>(
    &self,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>)
  ) -> Result<(G0, G1), DLEqError> {
    let capacity = G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY);
    if self.bits.len() != capacity.try_into().unwrap() {
      return Err(DLEqError::InvalidProofLength);
    }

    let keys = self.reconstruct_keys();
    Self::initialize_transcript(transcript, generators, keys);
    if !(
      self.poks.0.verify(transcript, generators.0.primary, keys.0) &&
      self.poks.1.verify(transcript, generators.1.primary, keys.1)
    ) {
      Err(DLEqError::InvalidProofOfKnowledge)?;
    }

    for (i, bit) in self.bits.iter().enumerate() {
      Self::transcript_bit(transcript, i, bit.commitments);

      let bit_e = (bit.e, scalar_convert(bit.e).ok_or(DLEqError::InvalidChallenge)?);
      if bit_e != Self::R_nonces(
        transcript.clone(),
        generators,
        bit.s[0],
        (
          bit.commitments.0 - generators.0.primary,
          bit.commitments.1 - generators.1.primary
        ),
        Self::R_nonces(
          transcript.clone(),
          generators,
          bit.s[1],
          bit.commitments,
          bit_e
        )
      ) {
        return Err(DLEqError::InvalidProof);
      }
    }

    Ok(keys)
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    for bit in &self.bits {
      bit.serialize(w)?;
    }
    self.poks.0.serialize(w)?;
    self.poks.1.serialize(w)
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<DLEqProof<G0, G1>> {
    let capacity = G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY);
    let mut bits = Vec::with_capacity(capacity.try_into().unwrap());
    for _ in 0 .. capacity {
      bits.push(Bit::deserialize(r)?);
    }
    Ok(DLEqProof { bits, poks: (SchnorrPoK::deserialize(r)?, SchnorrPoK::deserialize(r)?) })
  }
}
