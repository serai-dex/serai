use rand_core::{RngCore, CryptoRng};

use subtle::{ConstantTimeEq, ConditionallySelectable};

use transcript::Transcript;

use group::{ff::{Field, PrimeFieldBits}, prime::PrimeGroup};

use multiexp::BatchVerifier;

use crate::{
  Generators,
  cross_group::{DLEqError, scalar::{scalar_convert, mutual_scalar_from_bytes}, bits::RingSignature}
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use ff::PrimeField;
#[cfg(feature = "serialize")]
use crate::{read_scalar, cross_group::read_point};

#[allow(non_snake_case)]
fn nonces<
  T: Transcript,
  G0: PrimeGroup,
  G1: PrimeGroup
>(mut transcript: T, nonces: (G0, G1)) -> (G0::Scalar, G1::Scalar)
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  transcript.append_message(b"nonce_0", nonces.0.to_bytes().as_ref());
  transcript.append_message(b"nonce_1", nonces.1.to_bytes().as_ref());
  mutual_scalar_from_bytes(transcript.challenge(b"challenge").as_ref())
}

#[allow(non_snake_case)]
fn calculate_R<G0: PrimeGroup, G1: PrimeGroup>(
  generators: (Generators<G0>, Generators<G1>),
  s: (G0::Scalar, G1::Scalar),
  A: (G0, G1),
  e: (G0::Scalar, G1::Scalar)
) -> (G0, G1) {
  (((generators.0.alt * s.0) - (A.0 * e.0)), ((generators.1.alt * s.1) - (A.1 * e.1)))
}

#[allow(non_snake_case)]
fn R_nonces<T: Transcript, G0: PrimeGroup, G1: PrimeGroup>(
  transcript: T,
  generators: (Generators<G0>, Generators<G1>),
  s: (G0::Scalar, G1::Scalar),
  A: (G0, G1),
  e: (G0::Scalar, G1::Scalar)
) -> (G0::Scalar, G1::Scalar) where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  nonces(transcript, calculate_R(generators, s, A, e))
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClassicAos<G0: PrimeGroup, G1: PrimeGroup, const RING_LEN: usize> {
  // Merged challenges have a slight security reduction, yet one already applied to the scalar
  // being proven for, and this saves ~8kb. Alternatively, challenges could be redefined as a seed,
  // present here, which is then hashed for each of the two challenges, remaining unbiased/unique
  // while maintaining the bandwidth savings, yet also while adding 252 hashes for
  // Secp256k1/Ed25519
  e_0: G0::Scalar,
  s: [(G0::Scalar, G1::Scalar); RING_LEN]
}

impl<
  G0: PrimeGroup,
  G1: PrimeGroup,
  const RING_LEN: usize
> RingSignature<G0, G1> for ClassicAos<G0, G1, RING_LEN>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  type Context = ();

  const LEN: usize = RING_LEN;

  fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    ring: &[(G0, G1)],
    actual: usize,
    blinding_key: (G0::Scalar, G1::Scalar)
  ) -> Self {
    // While it is possible to use larger values, it's not efficient to do so
    // 2 + 2 == 2^2, yet 2 + 2 + 2 < 2^3
    debug_assert!((RING_LEN == 2) || (RING_LEN == 4));

    let mut e_0 = G0::Scalar::zero();
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); RING_LEN];

    let r = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
    #[allow(non_snake_case)]
    let original_R = (generators.0.alt * r.0, generators.1.alt * r.1);
    #[allow(non_snake_case)]
    let mut R = original_R;

    for i in ((actual + 1) .. (actual + RING_LEN + 1)).map(|i| i % RING_LEN) {
      let e = nonces(transcript.clone(), R);
      e_0 = G0::Scalar::conditional_select(&e_0, &e.0, usize::ct_eq(&i, &0));

      // Solve for the real index
      if i == actual {
        s[i] = (r.0 + (e.0 * blinding_key.0), r.1 + (e.1 * blinding_key.1));
        debug_assert_eq!(calculate_R(generators, s[i], ring[actual], e), original_R);
        break;
      // Generate a decoy response
      } else {
        s[i] = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      }

      R = calculate_R(generators, s[i], ring[i], e);
    }

    ClassicAos { e_0, s }
  }

  fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    _rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    _: &mut Self::Context,
    ring: &[(G0, G1)]
  ) -> Result<(), DLEqError> {
    debug_assert!((RING_LEN == 2) || (RING_LEN == 4));

    let e_0 = (self.e_0, scalar_convert(self.e_0).ok_or(DLEqError::InvalidChallenge)?);
    let mut e = None;
    for i in 0 .. RING_LEN {
      e = Some(R_nonces(transcript.clone(), generators, self.s[i], ring[i], e.unwrap_or(e_0)));
    }

    // Will panic if the above loop is never run somehow
    // If e wasn't an Option, and instead initially set to e_0, it'd always pass
     if e_0 != e.unwrap() {
       Err(DLEqError::InvalidProof)?;
     }
     Ok(())
  }

  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.e_0.to_repr().as_ref())?;
    for i in 0 .. Self::LEN {
      w.write_all(self.s[i].0.to_repr().as_ref())?;
      w.write_all(self.s[i].1.to_repr().as_ref())?;
    }
    Ok(())
  }

  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Self> {
    let e_0 = read_scalar(r)?;
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); RING_LEN];
    for i in 0 .. Self::LEN {
      s[i] = (read_scalar(r)?, read_scalar(r)?);
    }
    Ok(ClassicAos { e_0, s })
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MultiexpAos<G0: PrimeGroup, G1: PrimeGroup> {
  R_0: (G0, G1),
  s: [(G0::Scalar, G1::Scalar); 2]
}

impl<G0: PrimeGroup, G1: PrimeGroup> MultiexpAos<G0, G1> {
  #[allow(non_snake_case)]
  fn R_batch(
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar)
  ) -> (Vec<(G0::Scalar, G0)>, Vec<(G1::Scalar, G1)>) {
    (vec![(s.0, generators.0.alt), (-e.0, A.0)], vec![(s.1, generators.1.alt), (-e.1, A.1)])
  }
}

impl<G0: PrimeGroup, G1: PrimeGroup> RingSignature<G0, G1> for MultiexpAos<G0, G1>
  where G0::Scalar: PrimeFieldBits, G1::Scalar: PrimeFieldBits {
  type Context = (BatchVerifier<(), G0>, BatchVerifier<(), G1>);

  const LEN: usize = 2;

  fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    ring: &[(G0, G1)],
    actual: usize,
    blinding_key: (G0::Scalar, G1::Scalar)
  ) -> Self {
    #[allow(non_snake_case)]
    let mut R_0 = (G0::identity(), G1::identity());
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); 2]; // Can't use Self::LEN due to 76200

    let r = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
    #[allow(non_snake_case)]
    let original_R = (generators.0.alt * r.0, generators.1.alt * r.1);
    #[allow(non_snake_case)]
    let mut R = original_R;

    for i in ((actual + 1) .. (actual + Self::LEN + 1)).map(|i| i % Self::LEN) {
      if i == 0 {
        R_0.0 = R.0;
        R_0.1 = R.1;
      }

      // Solve for the real index
      let e = nonces(transcript.clone(), R);
      if i == actual {
        s[i] = (r.0 + (e.0 * blinding_key.0), r.1 + (e.1 * blinding_key.1));
        debug_assert_eq!(calculate_R(generators, s[i], ring[actual], e), original_R);
        break;
      // Generate a decoy response
      } else {
        s[i] = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      }

      R = calculate_R(generators, s[i], ring[i], e);
    }

    MultiexpAos { R_0, s }
  }

  fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    batch: &mut Self::Context,
    ring: &[(G0, G1)]
  ) -> Result<(), DLEqError> {
    let mut e = nonces(transcript.clone(), self.R_0);
    for i in 0 .. (Self::LEN - 1) {
      e = R_nonces(transcript.clone(), generators, self.s[i], ring[i], e);
    }

    let mut statements = Self::R_batch(
      generators,
      *self.s.last().unwrap(),
      *ring.last().unwrap(),
      e
    );
    statements.0.push((-G0::Scalar::one(), self.R_0.0));
    statements.1.push((-G1::Scalar::one(), self.R_0.1));
    batch.0.queue(&mut *rng, (), statements.0);
    batch.1.queue(&mut *rng, (), statements.1);

    Ok(())
  }

  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.R_0.0.to_bytes().as_ref())?;
    w.write_all(self.R_0.1.to_bytes().as_ref())?;
    for i in 0 .. Self::LEN {
      w.write_all(self.s[i].0.to_repr().as_ref())?;
      w.write_all(self.s[i].1.to_repr().as_ref())?;
    }
    Ok(())
  }

  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(r: &mut R) -> std::io::Result<Self> {
    #[allow(non_snake_case)]
    let R_0 = (read_point(r)?, read_point(r)?);
    let mut s = [(G0::Scalar::zero(), G1::Scalar::zero()); 2];
    for i in 0 .. Self::LEN {
      s[i] = (read_scalar(r)?, read_scalar(r)?);
    }
    Ok(MultiexpAos { R_0, s })
  }
}
