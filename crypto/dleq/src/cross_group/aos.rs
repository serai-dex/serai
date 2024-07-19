use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use group::{
  ff::{Field, PrimeFieldBits},
  prime::PrimeGroup,
};

use multiexp::BatchVerifier;

use crate::cross_group::{
  Generators, DLEqError,
  scalar::{scalar_convert, mutual_scalar_from_bytes},
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use ff::PrimeField;
#[cfg(feature = "serialize")]
use crate::{read_scalar, cross_group::read_point};

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Re<G0: PrimeGroup, G1: PrimeGroup> {
  R(G0, G1),
  // Merged challenges have a slight security reduction, yet one already applied to the scalar
  // being proven for, and this saves ~8kb. Alternatively, challenges could be redefined as a seed,
  // present here, which is then hashed for each of the two challenges, remaining unbiased/unique
  // while maintaining the bandwidth savings, yet also while adding 252 hashes for
  // Secp256k1/Ed25519
  e(G0::Scalar),
}

impl<G0: PrimeGroup, G1: PrimeGroup> Re<G0, G1> {
  #[allow(non_snake_case)]
  pub(crate) fn R_default() -> Re<G0, G1> {
    Re::R(G0::identity(), G1::identity())
  }

  pub(crate) fn e_default() -> Re<G0, G1> {
    Re::e(G0::Scalar::ZERO)
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Aos<G0: PrimeGroup + Zeroize, G1: PrimeGroup + Zeroize, const RING_LEN: usize> {
  Re_0: Re<G0, G1>,
  s: [(G0::Scalar, G1::Scalar); RING_LEN],
}

impl<
    G0: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    G1: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize,
    const RING_LEN: usize,
  > Aos<G0, G1, RING_LEN>
{
  #[allow(non_snake_case)]
  fn nonces<T: Transcript>(mut transcript: T, nonces: (G0, G1)) -> (G0::Scalar, G1::Scalar) {
    transcript.domain_separate(b"aos_membership_proof");
    transcript.append_message(b"ring_len", u8::try_from(RING_LEN).unwrap().to_le_bytes());
    transcript.append_message(b"nonce_0", nonces.0.to_bytes());
    transcript.append_message(b"nonce_1", nonces.1.to_bytes());
    mutual_scalar_from_bytes(transcript.challenge(b"challenge").as_ref())
  }

  #[allow(non_snake_case)]
  fn R(
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar),
  ) -> (G0, G1) {
    (((generators.0.alt * s.0) - (A.0 * e.0)), ((generators.1.alt * s.1) - (A.1 * e.1)))
  }

  #[allow(non_snake_case, clippy::type_complexity)]
  fn R_batch(
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar),
  ) -> (Vec<(G0::Scalar, G0)>, Vec<(G1::Scalar, G1)>) {
    (vec![(-s.0, generators.0.alt), (e.0, A.0)], vec![(-s.1, generators.1.alt), (e.1, A.1)])
  }

  #[allow(non_snake_case)]
  fn R_nonces<T: Transcript>(
    transcript: T,
    generators: (Generators<G0>, Generators<G1>),
    s: (G0::Scalar, G1::Scalar),
    A: (G0, G1),
    e: (G0::Scalar, G1::Scalar),
  ) -> (G0::Scalar, G1::Scalar) {
    Self::nonces(transcript, Self::R(generators, s, A, e))
  }

  #[allow(non_snake_case)]
  pub(crate) fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: &T,
    generators: (Generators<G0>, Generators<G1>),
    ring: &[(G0, G1)],
    mut actual: usize,
    blinding_key: &mut (G0::Scalar, G1::Scalar),
    mut Re_0: Re<G0, G1>,
  ) -> Self {
    // While it is possible to use larger values, it's not efficient to do so
    // 2 + 2 == 2^2, yet 2 + 2 + 2 < 2^3
    debug_assert!((RING_LEN == 2) || (RING_LEN == 4));
    debug_assert_eq!(RING_LEN, ring.len());

    let mut s = [(G0::Scalar::ZERO, G1::Scalar::ZERO); RING_LEN];

    let mut r = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
    #[allow(non_snake_case)]
    let original_R = (generators.0.alt * r.0, generators.1.alt * r.1);
    #[allow(non_snake_case)]
    let mut R = original_R;

    for i in ((actual + 1) ..= (actual + RING_LEN)).map(|i| i % RING_LEN) {
      let e = Self::nonces(transcript.clone(), R);
      if i == 0 {
        match Re_0 {
          Re::R(ref mut R0_0, ref mut R1_0) => {
            *R0_0 = R.0;
            *R1_0 = R.1
          }
          Re::e(ref mut e_0) => *e_0 = e.0,
        }
      }

      // Solve for the real index
      if i == actual {
        s[i] = (r.0 + (e.0 * blinding_key.0), r.1 + (e.1 * blinding_key.1));
        debug_assert_eq!(Self::R(generators, s[i], ring[actual], e), original_R);
        actual.zeroize();
        blinding_key.0.zeroize();
        blinding_key.1.zeroize();
        r.0.zeroize();
        r.1.zeroize();
        break;
      }

      // Generate a decoy response
      s[i] = (G0::Scalar::random(&mut *rng), G1::Scalar::random(&mut *rng));
      R = Self::R(generators, s[i], ring[i], e);
    }

    Aos { Re_0, s }
  }

  // Assumes the ring has already been transcripted in some form. Critically insecure if it hasn't
  pub(crate) fn verify<R: RngCore + CryptoRng, T: Clone + Transcript>(
    &self,
    rng: &mut R,
    transcript: &T,
    generators: (Generators<G0>, Generators<G1>),
    batch: &mut (BatchVerifier<(), G0>, BatchVerifier<(), G1>),
    ring: &[(G0, G1)],
  ) -> Result<(), DLEqError> {
    debug_assert!((RING_LEN == 2) || (RING_LEN == 4));
    debug_assert_eq!(RING_LEN, ring.len());

    #[allow(non_snake_case)]
    match self.Re_0 {
      Re::R(R0_0, R1_0) => {
        let mut e = Self::nonces(transcript.clone(), (R0_0, R1_0));
        #[allow(clippy::needless_range_loop)]
        for i in 0 .. (RING_LEN - 1) {
          e = Self::R_nonces(transcript.clone(), generators, self.s[i], ring[i], e);
        }

        let mut statements =
          Self::R_batch(generators, *self.s.last().unwrap(), *ring.last().unwrap(), e);
        statements.0.push((G0::Scalar::ONE, R0_0));
        statements.1.push((G1::Scalar::ONE, R1_0));
        batch.0.queue(&mut *rng, (), statements.0);
        batch.1.queue(&mut *rng, (), statements.1);
      }

      Re::e(e_0) => {
        let e_0 = (e_0, scalar_convert(e_0).ok_or(DLEqError::InvalidChallenge)?);
        let mut e = None;
        #[allow(clippy::needless_range_loop)]
        for i in 0 .. RING_LEN {
          e = Some(Self::R_nonces(
            transcript.clone(),
            generators,
            self.s[i],
            ring[i],
            e.unwrap_or(e_0),
          ));
        }

        // Will panic if the above loop is never run somehow
        // If e wasn't an Option, and instead initially set to e_0, it'd always pass
        if e_0 != e.unwrap() {
          Err(DLEqError::InvalidProof)?;
        }
      }
    }

    Ok(())
  }

  #[cfg(feature = "serialize")]
  pub(crate) fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    #[allow(non_snake_case)]
    match self.Re_0 {
      Re::R(R0, R1) => {
        w.write_all(R0.to_bytes().as_ref())?;
        w.write_all(R1.to_bytes().as_ref())?;
      }
      Re::e(e) => w.write_all(e.to_repr().as_ref())?,
    }

    for i in 0 .. RING_LEN {
      w.write_all(self.s[i].0.to_repr().as_ref())?;
      w.write_all(self.s[i].1.to_repr().as_ref())?;
    }

    Ok(())
  }

  #[allow(non_snake_case)]
  #[cfg(feature = "serialize")]
  pub(crate) fn read<R: Read>(r: &mut R, mut Re_0: Re<G0, G1>) -> std::io::Result<Self> {
    match Re_0 {
      Re::R(ref mut R0, ref mut R1) => {
        *R0 = read_point(r)?;
        *R1 = read_point(r)?
      }
      Re::e(ref mut e) => *e = read_scalar(r)?,
    }

    let mut s = [(G0::Scalar::ZERO, G1::Scalar::ZERO); RING_LEN];
    for s in &mut s {
      *s = (read_scalar(r)?, read_scalar(r)?);
    }

    Ok(Aos { Re_0, s })
  }
}
