use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use group::{ff::{Field, PrimeField, PrimeFieldBits}, prime::PrimeGroup};

use crate::{Generators, challenge};

pub mod scalar;
use scalar::scalar_normalize;

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
  e: (G0::Scalar, G1::Scalar),
  s: [(G0::Scalar, G1::Scalar); 2]
}

impl<G0: PrimeGroup, G1: PrimeGroup> Bit<G0, G1> {
  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.commitments.0.to_bytes().as_ref())?;
    w.write_all(self.commitments.1.to_bytes().as_ref())?;
    w.write_all(self.e.0.to_repr().as_ref())?;
    w.write_all(self.e.1.to_repr().as_ref())?;
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
        e: (read_scalar(r)?, read_scalar(r)?),
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

impl<G0: PrimeGroup, G1: PrimeGroup> DLEqProof<G0, G1> {
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
    (challenge(&mut transcript, b"challenge_G"), challenge(&mut transcript, b"challenge_H"))
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

  // TODO: Use multiexp here after https://github.com/serai-dex/serai/issues/17
  fn reconstruct_key<G: PrimeGroup>(commitments: impl Iterator<Item = G>) -> G {
    let mut pow_2 = G::Scalar::one();
    commitments.fold(G::identity(), |key, commitment| {
      let res = key + (commitment * pow_2);
      pow_2 = pow_2.double();
      res
    })
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
  ) -> (
    Self,
    (G0::Scalar, G1::Scalar)
  ) where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
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
      // TODO: Not constant time
      if *bit {
        commitments.0 += generators.0.primary;
        commitments.1 += generators.1.primary;
      }
      Self::transcript_bit(transcript, i, commitments);

      let nonces = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      let e_0 = Self::nonces(
        transcript.clone(),
        ((generators.0.alt * nonces.0), (generators.1.alt * nonces.1))
      );
      let s_0 = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));

      let e_1 = Self::R_nonces(
        transcript.clone(),
        generators,
        (s_0.0, s_0.1),
        if *bit {
          commitments
        } else {
          ((commitments.0 - generators.0.primary), (commitments.1 - generators.1.primary))
        },
        e_0
      );
      let s_1 = (nonces.0 + (e_1.0 * blinding_key.0), nonces.1 + (e_1.1 * blinding_key.1));

      bits.push(
        if *bit {
          Bit { commitments, e: e_0, s: [s_1, s_0] }
        } else {
          Bit { commitments, e: e_1, s: [s_0, s_1] }
        }
      );

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
  ) -> Result<(G0, G1), DLEqError> where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
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

      if bit.e != Self::R_nonces(
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
          bit.e
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
