use core::ops::{Deref, DerefMut};
#[cfg(feature = "serialize")]
use std::io::{self, Read, Write};

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use digest::{Digest, HashMarker};

use transcript::Transcript;

use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  prime::PrimeGroup,
};
use multiexp::BatchVerifier;

/// Scalar utilities.
pub mod scalar;
use scalar::{scalar_convert, mutual_scalar_from_bytes};

pub(crate) mod schnorr;
use self::schnorr::SchnorrPoK;

pub(crate) mod aos;

mod bits;
use bits::{BitSignature, Bits};

// Use black_box when possible
#[rustversion::since(1.66)]
use core::hint::black_box;
#[rustversion::before(1.66)]
fn black_box<T>(val: T) -> T {
  val
}

fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  #[allow(clippy::cast_lossless)]
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
}

#[cfg(feature = "serialize")]
pub(crate) fn read_point<R: Read, G: PrimeGroup>(r: &mut R) -> io::Result<G> {
  let mut repr = G::Repr::default();
  r.read_exact(repr.as_mut())?;
  let point = G::from_bytes(&repr);
  let Some(point) = Option::<G>::from(point) else { Err(io::Error::other("invalid point"))? };
  if point.to_bytes().as_ref() != repr.as_ref() {
    Err(io::Error::other("non-canonical point"))?;
  }
  Ok(point)
}

/// A pair of generators, one committing to values (primary), one blinding (alt), for an elliptic
/// curve.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Generators<G: PrimeGroup> {
  /// The generator used to commit to values.
  ///
  /// This should likely be the curve's traditional 'basepoint'.
  pub primary: G,
  /// The generator used to blind values. This must be distinct from the primary generator.
  pub alt: G,
}

impl<G: PrimeGroup> Generators<G> {
  /// Create a new set of generators.
  pub fn new(primary: G, alt: G) -> Option<Generators<G>> {
    if primary == alt {
      None?;
    }
    Some(Generators { primary, alt })
  }

  fn transcript<T: Transcript>(&self, transcript: &mut T) {
    transcript.domain_separate(b"generators");
    transcript.append_message(b"primary", self.primary.to_bytes());
    transcript.append_message(b"alternate", self.alt.to_bytes());
  }
}

/// Error for cross-group DLEq proofs.
#[derive(Error, PartialEq, Eq, Debug)]
pub enum DLEqError {
  /// Invalid proof length.
  #[error("invalid proof length")]
  InvalidProofLength,
  /// Invalid challenge.
  #[error("invalid challenge")]
  InvalidChallenge,
  /// Invalid proof.
  #[error("invalid proof")]
  InvalidProof,
}

// This should never be directly instantiated and uses a u8 to represent internal values
// Any external usage is likely invalid
#[doc(hidden)]
// Debug would be such a dump of data this likely isn't helpful, but at least it's available to
// anyone who wants it
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct __DLEqProof<
  G0: PrimeGroup<Scalar: PrimeFieldBits> + Zeroize,
  G1: PrimeGroup<Scalar: PrimeFieldBits> + Zeroize,
  const SIGNATURE: u8,
  const RING_LEN: usize,
  const REMAINDER_RING_LEN: usize,
> {
  bits: Vec<Bits<G0, G1, SIGNATURE, RING_LEN>>,
  remainder: Option<Bits<G0, G1, SIGNATURE, REMAINDER_RING_LEN>>,
  poks: (SchnorrPoK<G0>, SchnorrPoK<G1>),
}

macro_rules! dleq {
  ($doc_str: expr, $name: ident, $signature: expr, $remainder: literal,) => {
    #[doc = $doc_str]
    pub type $name<G0, G1> = __DLEqProof<
      G0,
      G1,
      { $signature.to_u8() },
      { $signature.ring_len() },
      // There may not be a remainder, yet if there is one, it'll be just one bit
      // A ring for one bit has a RING_LEN of 2
      {
        if $remainder {
          2
        } else {
          0
        }
      },
    >;
  };
}

// Proves for 1-bit at a time with the signature form (e, s), as originally described in MRL-0010.
// Uses a merged challenge, unlike MRL-0010, for the ring signature, saving an element from each
// bit and removing a hash while slightly reducing challenge security. This security reduction is
// already applied to the scalar being proven for, a result of the requirement it's mutually valid
// over both scalar fields, hence its application here as well. This is mainly here as a point of
// reference for the following DLEq proofs, all which use merged challenges, and isn't performant
// in comparison to the others
dleq!(
  "The DLEq proof described in MRL-0010.",
  ClassicLinearDLEq,
  BitSignature::ClassicLinear,
  false,
);

// Proves for 2-bits at a time to save 3/7 elements of every other bit
// <9% smaller than CompromiseLinear, yet ~12% slower
dleq!(
  "A DLEq proof modified from MRL-0010, proving for two bits at a time to save on space.",
  ConciseLinearDLEq,
  BitSignature::ConciseLinear,
  true,
);

// Uses AOS signatures of the form R, s, to enable the final step of the ring signature to be
// batch verified, at the cost of adding an additional element per bit
dleq!(
  "
    A DLEq proof modified from MRL-0010, using R, s forms instead of c, s forms to enable batch
    verification at the cost of space usage.
  ",
  EfficientLinearDLEq,
  BitSignature::EfficientLinear,
  false,
);

// Proves for 2-bits at a time while using the R, s form. This saves 3/7 elements of every other
// bit, while adding 1 element to every bit, and is more efficient than ConciseLinear yet less
// efficient than EfficientLinear due to having more ring signature steps which aren't batched
// >25% smaller than EfficientLinear and just 11% slower, making it the recommended option
dleq!(
  "
    A DLEq proof modified from MRL-0010, using R, s forms instead of c, s forms, while proving for
    two bits at a time, to enable batch verification and take advantage of space savings.

    This isn't quite as efficient as EfficientLinearDLEq, and isn't as compact as
    ConciseLinearDLEq, yet strikes a strong balance of performance and conciseness.
  ",
  CompromiseLinearDLEq,
  BitSignature::CompromiseLinear,
  true,
);

impl<
    G0: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    G1: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    const SIGNATURE: u8,
    const RING_LEN: usize,
    const REMAINDER_RING_LEN: usize,
  > __DLEqProof<G0, G1, SIGNATURE, RING_LEN, REMAINDER_RING_LEN>
{
  pub(crate) fn transcript<T: Transcript>(
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    keys: (G0, G1),
  ) {
    transcript.domain_separate(b"cross_group_dleq");
    generators.0.transcript(transcript);
    generators.1.transcript(transcript);
    transcript.domain_separate(b"points");
    transcript.append_message(b"point_0", keys.0.to_bytes());
    transcript.append_message(b"point_1", keys.1.to_bytes());
  }

  pub(crate) fn blinding_key<R: RngCore + CryptoRng, F: PrimeField>(
    rng: &mut R,
    total: &mut F,
    last: bool,
  ) -> F {
    let blinding_key = if last { -*total } else { F::random(&mut *rng) };
    *total += blinding_key;
    blinding_key
  }

  fn reconstruct_keys(&self) -> (G0, G1) {
    let mut res = (
      self.bits.iter().map(|bit| bit.commitments.0).sum::<G0>(),
      self.bits.iter().map(|bit| bit.commitments.1).sum::<G1>(),
    );

    if let Some(bit) = &self.remainder {
      res.0 += bit.commitments.0;
      res.1 += bit.commitments.1;
    }

    res
  }

  #[allow(clippy::type_complexity)]
  fn prove_internal<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    f: (Zeroizing<G0::Scalar>, Zeroizing<G1::Scalar>),
  ) -> (Self, (Zeroizing<G0::Scalar>, Zeroizing<G1::Scalar>)) {
    Self::transcript(
      transcript,
      generators,
      ((generators.0.primary * f.0.deref()), (generators.1.primary * f.1.deref())),
    );

    let poks = (
      SchnorrPoK::<G0>::prove(rng, transcript, generators.0.primary, &f.0),
      SchnorrPoK::<G1>::prove(rng, transcript, generators.1.primary, &f.1),
    );

    let mut blinding_key_total = (G0::Scalar::ZERO, G1::Scalar::ZERO);
    let mut blinding_key = |rng: &mut R, last| {
      let blinding_key = (
        Self::blinding_key(&mut *rng, &mut blinding_key_total.0, last),
        Self::blinding_key(&mut *rng, &mut blinding_key_total.1, last),
      );
      if last {
        debug_assert_eq!(blinding_key_total.0, G0::Scalar::ZERO);
        debug_assert_eq!(blinding_key_total.1, G1::Scalar::ZERO);
      }
      blinding_key
    };

    let capacity = usize::try_from(G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY)).unwrap();
    let bits_per_group = usize::from(BitSignature::from(SIGNATURE).bits());

    let mut pow_2 = (generators.0.primary, generators.1.primary);

    let mut raw_bits = f.0.to_le_bits();
    let mut bits = Vec::with_capacity(capacity);
    let mut these_bits: u8 = 0;
    // Needed to zero out the bits
    #[allow(unused_assignments)]
    for (i, mut bit) in raw_bits.iter_mut().enumerate() {
      if i == capacity {
        break;
      }

      // Accumulate this bit
      let mut bit = u8_from_bool(bit.deref_mut());
      these_bits |= bit << (i % bits_per_group);
      bit.zeroize();

      if (i % bits_per_group) == (bits_per_group - 1) {
        let last = i == (capacity - 1);
        let mut blinding_key = blinding_key(&mut *rng, last);
        bits.push(Bits::prove(
          &mut *rng,
          transcript,
          generators,
          i / bits_per_group,
          &mut pow_2,
          these_bits,
          &mut blinding_key,
        ));
        these_bits.zeroize();
      }
    }
    debug_assert_eq!(bits.len(), capacity / bits_per_group);

    let mut remainder = None;
    if capacity != ((capacity / bits_per_group) * bits_per_group) {
      let mut blinding_key = blinding_key(&mut *rng, true);
      remainder = Some(Bits::prove(
        &mut *rng,
        transcript,
        generators,
        capacity / bits_per_group,
        &mut pow_2,
        these_bits,
        &mut blinding_key,
      ));
    }

    these_bits.zeroize();

    let proof = __DLEqProof { bits, remainder, poks };
    debug_assert_eq!(
      proof.reconstruct_keys(),
      (generators.0.primary * f.0.deref(), generators.1.primary * f.1.deref())
    );
    (proof, f)
  }

  /// Prove the Cross-Group Discrete Log Equality for the points derived from the scalar created as
  /// the output of the passed in Digest.
  ///
  /// Given the non-standard requirements to achieve uniformity, needing to be < 2^x instead of
  /// less than a prime moduli, this is the simplest way to safely and securely generate a Scalar,
  /// without risk of failure nor bias.
  ///
  /// It also ensures a lack of determinable relation between keys, guaranteeing security in the
  /// currently expected use case for this, atomic swaps, where each swap leaks the key. Knowing
  /// the relationship between keys would allow breaking all swaps after just one.
  #[allow(clippy::type_complexity)]
  pub fn prove<R: RngCore + CryptoRng, T: Clone + Transcript, D: Digest + HashMarker>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    digest: D,
  ) -> (Self, (Zeroizing<G0::Scalar>, Zeroizing<G1::Scalar>)) {
    // This pattern theoretically prevents the compiler from moving it, so our protection against
    // a copy remaining un-zeroized is actually what's causing a copy. There's still a feeling of
    // safety granted by it, even if there's a loss in performance.
    let (mut f0, mut f1) =
      mutual_scalar_from_bytes::<G0::Scalar, G1::Scalar>(digest.finalize().as_ref());
    let f = (Zeroizing::new(f0), Zeroizing::new(f1));
    f0.zeroize();
    f1.zeroize();

    Self::prove_internal(rng, transcript, generators, f)
  }

  /// Prove the Cross-Group Discrete Log Equality for the points derived from the scalar passed in,
  /// failing if it's not mutually valid.
  ///
  /// This allows for rejection sampling externally derived scalars until they're safely usable,
  /// as needed.
  #[allow(clippy::type_complexity)]
  pub fn prove_without_bias<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
    f0: Zeroizing<G0::Scalar>,
  ) -> Option<(Self, (Zeroizing<G0::Scalar>, Zeroizing<G1::Scalar>))> {
    scalar_convert(*f0.deref()) // scalar_convert will zeroize it, though this is unfortunate
      .map(|f1| Self::prove_internal(rng, transcript, generators, (f0, Zeroizing::new(f1))))
  }

  /// Verify a Cross-Group Discrete Log Equality proof, returning the points proven for.
  pub fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generators: (Generators<G0>, Generators<G1>),
  ) -> Result<(G0, G1), DLEqError> {
    let capacity = usize::try_from(G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY)).unwrap();
    let bits_per_group = usize::from(BitSignature::from(SIGNATURE).bits());
    let has_remainder = (capacity % bits_per_group) != 0;

    // These shouldn't be possible, as locally created and deserialized proofs should be properly
    // formed in these regards, yet it doesn't hurt to check and would be problematic if true
    if (self.bits.len() != (capacity / bits_per_group)) ||
      ((self.remainder.is_none() && has_remainder) ||
        (self.remainder.is_some() && !has_remainder))
    {
      return Err(DLEqError::InvalidProofLength);
    }

    let keys = self.reconstruct_keys();
    Self::transcript(transcript, generators, keys);

    let batch_capacity = match BitSignature::from(SIGNATURE) {
      BitSignature::ClassicLinear | BitSignature::ConciseLinear => 3,
      BitSignature::EfficientLinear | BitSignature::CompromiseLinear => (self.bits.len() + 1) * 3,
    };
    let mut batch = (BatchVerifier::new(batch_capacity), BatchVerifier::new(batch_capacity));

    self.poks.0.verify(&mut *rng, transcript, generators.0.primary, keys.0, &mut batch.0);
    self.poks.1.verify(&mut *rng, transcript, generators.1.primary, keys.1, &mut batch.1);

    let mut pow_2 = (generators.0.primary, generators.1.primary);
    for (i, bits) in self.bits.iter().enumerate() {
      bits.verify(&mut *rng, transcript, generators, &mut batch, i, &mut pow_2)?;
    }
    if let Some(bit) = &self.remainder {
      bit.verify(&mut *rng, transcript, generators, &mut batch, self.bits.len(), &mut pow_2)?;
    }

    if (!batch.0.verify_vartime()) || (!batch.1.verify_vartime()) {
      Err(DLEqError::InvalidProof)?;
    }

    Ok(keys)
  }

  /// Write a Cross-Group Discrete Log Equality proof to a type satisfying std::io::Write.
  #[cfg(feature = "serialize")]
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for bit in &self.bits {
      bit.write(w)?;
    }
    if let Some(bit) = &self.remainder {
      bit.write(w)?;
    }
    self.poks.0.write(w)?;
    self.poks.1.write(w)
  }

  /// Read a Cross-Group Discrete Log Equality proof from a type satisfying std::io::Read.
  #[cfg(feature = "serialize")]
  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    let capacity = usize::try_from(G0::Scalar::CAPACITY.min(G1::Scalar::CAPACITY)).unwrap();
    let bits_per_group = usize::from(BitSignature::from(SIGNATURE).bits());

    let mut bits = Vec::with_capacity(capacity / bits_per_group);
    for _ in 0 .. (capacity / bits_per_group) {
      bits.push(Bits::read(r)?);
    }

    let mut remainder = None;
    if (capacity % bits_per_group) != 0 {
      remainder = Some(Bits::read(r)?);
    }

    Ok(__DLEqProof { bits, remainder, poks: (SchnorrPoK::read(r)?, SchnorrPoK::read(r)?) })
  }
}
