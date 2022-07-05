use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use digest::Digest;

use subtle::{ConstantTimeEq, ConditionallySelectable};

use transcript::Transcript;

use group::{ff::{Field, PrimeField, PrimeFieldBits}, prime::PrimeGroup};

use crate::Generators;

pub mod scalar;
use scalar::{scalar_convert, mutual_scalar_from_bytes};

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
pub struct Bits<G0: PrimeGroup, G1: PrimeGroup, const POSSIBLE_VALUES: usize> {
  commitments: (G0, G1),
  // Merged challenges have a slight security reduction, yet one already applied to the scalar
  // being proven for, and this saves ~8kb. Alternatively, challenges could be redefined as a seed,
  // present here, which is then hashed for each of the two challenges, remaining unbiased/unique
  // while maintaining the bandwidth savings, yet also while adding 252 hashes for
  // Secp256k1/Ed25519
  e_0: G0::Scalar,
  s: [(G0::Scalar, G1::Scalar); POSSIBLE_VALUES]
}

impl<G0: PrimeGroup, G1: PrimeGroup, const POSSIBLE_VALUES: usize> Bits<G0, G1, POSSIBLE_VALUES>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  pub fn transcript<T: Transcript>(transcript: &mut T, i: usize, commitments: (G0, G1)) {
    if i == 0 {
      transcript.domain_separate(b"cross_group_dleq");
    }
    transcript.append_message(b"bit_group", &u16::try_from(i).unwrap().to_le_bytes());
    transcript.append_message(b"commitment_0", commitments.0.to_bytes().as_ref());
    transcript.append_message(b"commitment_1", commitments.1.to_bytes().as_ref());
  }

  #[allow(non_snake_case)]
  fn nonces<T: Transcript>(mut transcript: T, nonces: (G0, G1)) -> (G0::Scalar, G1::Scalar) {
    transcript.append_message(b"nonce_0", nonces.0.to_bytes().as_ref());
    transcript.append_message(b"nonce_1", nonces.1.to_bytes().as_ref());
    mutual_scalar_from_bytes(transcript.challenge(b"challenge").as_ref())
  }

  #[allow(non_snake_case)]
  fn R(
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar)
  ) -> (G0, G1) {
    (((generators.0.alt * s.0) - (A.0 * e.0)), ((generators.1.alt * s.1) - (A.1 * e.1)))
  }

  #[allow(non_snake_case)]
  fn R_nonces<T: Transcript>(
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar)
  ) -> (G0::Scalar, G1::Scalar) {
    Self::nonces(transcript, Self::R(generators, s, A, e))
  }

  fn ring(pow_2: (G0, G1), commitments: (G0, G1)) -> [(G0, G1); POSSIBLE_VALUES] {
    let mut res = [(G0::identity(), G1::identity()); POSSIBLE_VALUES];
    res[POSSIBLE_VALUES - 1] = commitments;
    for i in (0 .. (POSSIBLE_VALUES - 1)).rev() {
      res[i] = (res[i + 1].0 - pow_2.0, res[i + 1].1 - pow_2.1);
    }
    res
  }

  pub fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    i: usize,
    pow_2: &mut (G0, G1),
    bits: u8,
    blinding_key: (G0::Scalar, G1::Scalar)
  ) -> Bits<G0, G1, POSSIBLE_VALUES> {
    // While it is possible to use larger values, it's not efficient to do so
    // 2 + 2 == 2^2, yet 2 + 2 + 2 < 2^3
    debug_assert!((POSSIBLE_VALUES == 2) || (POSSIBLE_VALUES == 4));

    let mut commitments = (
      (generators.0.alt * blinding_key.0),
      (generators.1.alt * blinding_key.1)
    );
    commitments.0 += pow_2.0 * G0::Scalar::from(bits.into());
    commitments.1 += pow_2.1 * G1::Scalar::from(bits.into());
    Self::transcript(transcript, i, commitments);

    let ring = Self::ring(*pow_2, commitments);
    // Invert the index to get the raw blinding key's position in the ring
    let actual = POSSIBLE_VALUES - 1 - usize::from(bits);

    let mut e_0 = G0::Scalar::zero();
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); POSSIBLE_VALUES];

    let r = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
    #[allow(non_snake_case)]
    let original_R = (generators.0.alt * r.0, generators.1.alt * r.1);
    #[allow(non_snake_case)]
    let mut R = original_R;

    for i in ((actual + 1) .. (actual + POSSIBLE_VALUES + 1)).map(|i| i % POSSIBLE_VALUES) {
      let e = Self::nonces(transcript.clone(), R);
      e_0 = G0::Scalar::conditional_select(&e_0, &e.0, usize::ct_eq(&i, &0));

      // Solve for the real index
      if i == actual {
        s[i] = (r.0 + (e.0 * blinding_key.0), r.1 + (e.1 * blinding_key.1));
        debug_assert_eq!(Self::R(generators, s[i], ring[actual], e), original_R);
        break;
      // Generate a decoy response
      } else {
        s[i] = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      }

      R = Self::R(generators, s[i], ring[i], e);
    }

    pow_2.0 = pow_2.0.double();
    pow_2.1 = pow_2.1.double();
    if POSSIBLE_VALUES == 4 {
      pow_2.0 = pow_2.0.double();
      pow_2.1 = pow_2.1.double();
    }

    Bits { commitments, e_0, s }
  }

  pub fn verify<T: Clone + Transcript>(
    &self,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    i: usize,
    pow_2: &mut (G0, G1)
  ) -> Result<(), DLEqError> {
    debug_assert!((POSSIBLE_VALUES == 2) || (POSSIBLE_VALUES == 4));

    Self::transcript(transcript, i, self.commitments);

    let ring = Self::ring(*pow_2, self.commitments);
    let e_0 = (self.e_0, scalar_convert(self.e_0).ok_or(DLEqError::InvalidChallenge)?);
    let mut e = None;
    for i in 0 .. POSSIBLE_VALUES {
      e = Some(
        Self::R_nonces(transcript.clone(), generators, self.s[i], ring[i], e.unwrap_or(e_0))
      );
    }

    // Will panic if the above loop is never run somehow
    // If e wasn't an Option, and instead initially set to e_0, it'd always pass
    if e_0 != e.unwrap() {
      return Err(DLEqError::InvalidProof);
    }

    pow_2.0 = pow_2.0.double();
    pow_2.1 = pow_2.1.double();
    if POSSIBLE_VALUES == 4 {
      pow_2.0 = pow_2.0.double();
      pow_2.1 = pow_2.1.double();
    }

    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.commitments.0.to_bytes().as_ref())?;
    w.write_all(self.commitments.1.to_bytes().as_ref())?;
    w.write_all(self.e_0.to_repr().as_ref())?;
    for i in 0 .. POSSIBLE_VALUES {
      w.write_all(self.s[i].0.to_repr().as_ref())?;
      w.write_all(self.s[i].1.to_repr().as_ref())?;
    }
    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Bits<G0, G1, POSSIBLE_VALUES>> {
    let commitments = (read_point(r)?, read_point(r)?);
    let e_0 = read_scalar(r)?;
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); POSSIBLE_VALUES];
    for i in 0 .. POSSIBLE_VALUES {
      s[i] = (read_scalar(r)?, read_scalar(r)?);
    }
    Ok(Bits { commitments, e_0, s })
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
  bits: Vec<Bits<G0, G1, 4>>,
  remainder: Option<Bits<G0, G1, 2>>,
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
    let remainder = self.remainder
      .as_ref()
      .map(|bit| bit.commitments)
      .unwrap_or((G0::identity(), G1::identity()));
    (
      self.bits.iter().map(|bit| bit.commitments.0).sum::<G0>() + remainder.0,
      self.bits.iter().map(|bit| bit.commitments.1).sum::<G1>() + remainder.1
    )
  }

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
  pub fn verify<T: Clone + Transcript>(
    &self,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>)
  ) -> Result<(G0, G1), DLEqError> {
    let capacity = G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY);
    if (self.bits.len() != (capacity / 2).try_into().unwrap()) || (
      // This shouldn't be possible, as deserialize ensures this is present for fields with this
      // characteristic, and proofs locally generated will have it. Regardless, best to ensure
      self.remainder.is_none() && ((capacity % 2) == 1)
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
      bits.verify(transcript, generators, i, &mut pow_2)?;
    }
    if let Some(bit) = &self.remainder {
      bit.verify(transcript, generators, self.bits.len(), &mut pow_2)?;
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
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<DLEqProof<G0, G1>> {
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
