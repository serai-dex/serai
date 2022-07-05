use rand_core::{RngCore, CryptoRng};

use digest::Digest;

use transcript::Transcript;

use group::{ff::{Field, PrimeField, PrimeFieldBits}, prime::PrimeGroup};

use crate::{
  Generators,
  cross_group::{
    DLEqError, DLEqProof,
    scalar::{scalar_convert, mutual_scalar_from_bytes},
    schnorr::SchnorrPoK,
    linear::aos::ClassicAos,
    bits::Bits
  }
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};

pub type ConciseDLEq<G0, G1> = DLEqProof<
  G0,
  G1,
  ClassicAos<G0, G1, 4>,
  ClassicAos<G0, G1, 2>
 >;

impl<G0: PrimeGroup, G1: PrimeGroup> ConciseDLEq<G0, G1>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  fn prove_internal<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    f: (G0::Scalar, G1::Scalar)
  ) -> (Self, (G0::Scalar, G1::Scalar)) {
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
    let mut blinding_key = |rng: &mut R, last| {
      let blinding_key = (
        Self::blinding_key(&mut *rng, &mut blinding_key_total.0, last),
        Self::blinding_key(&mut *rng, &mut blinding_key_total.1, last)
      );
      if last {
        debug_assert_eq!(blinding_key_total.0, G0::Scalar::zero());
        debug_assert_eq!(blinding_key_total.1, G1::Scalar::zero());
      }
      blinding_key
    };

    let mut pow_2 = (generators.0.primary, generators.1.primary);

    let raw_bits = f.0.to_le_bits();
    let capacity = usize::try_from(G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY)).unwrap();
    let mut bits = Vec::with_capacity(capacity);
    let mut these_bits: u8 = 0;
    for (i, bit) in raw_bits.iter().enumerate() {
      if i > ((capacity / 2) * 2) {
        break;
      }

      let bit = *bit as u8;
      debug_assert_eq!(bit | 1, 1);

      if (i % 2) == 0 {
        these_bits = bit;
        continue;
      } else {
        these_bits += bit << 1;
      }

      let last = i == (capacity - 1);
      let blinding_key = blinding_key(&mut *rng, last);
      bits.push(
        Bits::prove(&mut *rng, transcript, generators, i / 2, &mut pow_2, these_bits, blinding_key)
      );
    }

    let mut remainder = None;
    if (capacity % 2) == 1 {
      let blinding_key = blinding_key(&mut *rng, true);
      remainder = Some(
        Bits::prove(
          &mut *rng,
          transcript,
          generators,
          capacity / 2,
          &mut pow_2,
          these_bits,
          blinding_key
        )
      );
    }

    let proof = DLEqProof { bits, remainder, poks };
    debug_assert_eq!(
      proof.reconstruct_keys(),
      (generators.0.primary * f.0, generators.1.primary * f.1)
    );
    (proof, f)
  }

  /// Prove the cross-Group Discrete Log Equality for the points derived from the scalar created as
  /// the output of the passed in Digest. Given the non-standard requirements to achieve
  /// uniformity, needing to be < 2^x instead of less than a prime moduli, this is the simplest way
  /// to safely and securely generate a Scalar, without risk of failure, nor bias
  /// It also ensures a lack of determinable relation between keys, guaranteeing security in the
  /// currently expected use case for this, atomic swaps, where each swap leaks the key. Knowing
  /// the relationship between keys would allow breaking all swaps after just one
  pub fn prove<R: RngCore + CryptoRng, T: Clone + Transcript, D: Digest>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    digest: D
  ) -> (Self, (G0::Scalar, G1::Scalar)) {
    Self::prove_internal(
      rng,
      transcript,
      generators,
      mutual_scalar_from_bytes(digest.finalize().as_ref())
    )
  }

  /// Prove the cross-Group Discrete Log Equality for the points derived from the scalar passed in,
  /// failing if it's not mutually valid. This allows for rejection sampling externally derived
  /// scalars until they're safely usable, as needed
  pub fn prove_without_bias<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    f0: G0::Scalar
  ) -> Option<(Self, (G0::Scalar, G1::Scalar))> {
    scalar_convert(f0).map(|f1| Self::prove_internal(rng, transcript, generators, (f0, f1)))
  }

  /// Verify a cross-Group Discrete Log Equality statement, returning the points proven for
  pub fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>)
  ) -> Result<(G0, G1), DLEqError> {
    let capacity = G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY);
    if (self.bits.len() != (capacity / 2).try_into().unwrap()) || (
      // These shouldn't be possible, as deserialize ensures this is present for fields with this
      // characteristic, and proofs locally generated will have it. Regardless, best to ensure
      (self.remainder.is_none() && ((capacity % 2) == 1)) ||
      (self.remainder.is_some() && ((capacity % 2) == 0))
    ) {
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

    let mut pow_2 = (generators.0.primary, generators.1.primary);
    for (i, bits) in self.bits.iter().enumerate() {
      bits.verify(&mut *rng, transcript, generators, &mut (), i, &mut pow_2)?;
    }
    if let Some(bit) = &self.remainder {
      bit.verify(&mut *rng, transcript, generators, &mut (), self.bits.len(), &mut pow_2)?;
    }

    Ok(keys)
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    for bit in &self.bits {
      bit.serialize(w)?;
    }
    if let Some(bit) = &self.remainder {
      bit.serialize(w)?;
    }
    self.poks.0.serialize(w)?;
    self.poks.1.serialize(w)
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Self> {
    let capacity = G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY);
    let mut bits = Vec::with_capacity(capacity.try_into().unwrap());
    for _ in 0 .. (capacity / 2) {
      bits.push(Bits::deserialize(r)?);
    }

    let mut remainder = None;
    if (capacity % 2) == 1 {
      remainder = Some(Bits::deserialize(r)?);
    }

    Ok(
      DLEqProof {
        bits,
        remainder,
        poks: (SchnorrPoK::deserialize(r)?, SchnorrPoK::deserialize(r)?)
      }
    )
  }
}
