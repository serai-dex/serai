use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use curve::{
  ff::Field,
  group::{Group, GroupEncoding},
  Curve, CurveError,
};
use multiexp::BatchVerifier;

use crate::cross_group::{
  Generators, DLEqError,
  scalar::{scalar_convert, mutual_scalar_from_bytes},
};

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use curve::ff::PrimeField;

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Re<C0: Curve, C1: Curve> {
  R(C0::G, C1::G),
  // Merged challenges have a slight security reduction, yet one already applied to the scalar
  // being proven for, and this saves ~8kb. Alternatively, challenges could be redefined as a seed,
  // present here, which is then hashed for each of the two challenges, remaining unbiased/unique
  // while maintaining the bandwidth savings, yet also while adding 252 hashes for
  // Secp256k1/Ed25519
  e(C0::F),
}

impl<C0: Curve, C1: Curve> Re<C0, C1> {
  #[allow(non_snake_case)]
  pub(crate) fn R_default() -> Re<C0, C1> {
    Re::R(C0::G::identity(), C1::G::identity())
  }

  pub(crate) fn e_default() -> Re<C0, C1> {
    Re::e(C0::F::zero())
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Aos<C0: Curve, C1: Curve, const RING_LEN: usize> {
  Re_0: Re<C0, C1>,
  s: [(C0::F, C1::F); RING_LEN],
}

impl<C0: Curve, C1: Curve, const RING_LEN: usize> Aos<C0, C1, RING_LEN> {
  #[allow(non_snake_case)]
  fn nonces<T: Transcript>(mut transcript: T, nonces: (C0::G, C1::G)) -> (C0::F, C1::F) {
    transcript.domain_separate(b"aos_membership_proof");
    transcript.append_message(b"ring_len", &u8::try_from(RING_LEN).unwrap().to_le_bytes());
    transcript.append_message(b"nonce_0", nonces.0.to_bytes().as_ref());
    transcript.append_message(b"nonce_1", nonces.1.to_bytes().as_ref());
    mutual_scalar_from_bytes(transcript.challenge(b"challenge").as_ref())
  }

  #[allow(non_snake_case)]
  fn R(
    generators: (Generators<C0::G>, Generators<C1::G>),
    s: (C0::F, C1::F),
    A: (C0::G, C1::G),
    e: (C0::F, C1::F),
  ) -> (C0::G, C1::G) {
    (((generators.0.alt * s.0) - (A.0 * e.0)), ((generators.1.alt * s.1) - (A.1 * e.1)))
  }

  #[allow(non_snake_case)]
  fn R_batch(
    generators: (Generators<C0::G>, Generators<C1::G>),
    s: (C0::F, C1::F),
    A: (C0::G, C1::G),
    e: (C0::F, C1::F),
  ) -> (Vec<(C0::F, C0::G)>, Vec<(C1::F, C1::G)>) {
    (vec![(-s.0, generators.0.alt), (e.0, A.0)], vec![(-s.1, generators.1.alt), (e.1, A.1)])
  }

  #[allow(non_snake_case)]
  fn R_nonces<T: Transcript>(
    transcript: T,
    generators: (Generators<C0::G>, Generators<C1::G>),
    s: (C0::F, C1::F),
    A: (C0::G, C1::G),
    e: (C0::F, C1::F),
  ) -> (C0::F, C1::F) {
    Self::nonces(transcript, Self::R(generators, s, A, e))
  }

  #[allow(non_snake_case)]
  pub(crate) fn prove<R: RngCore + CryptoRng, T: Clone + Transcript>(
    rng: &mut R,
    transcript: T,
    generators: (Generators<C0::G>, Generators<C1::G>),
    ring: &[(C0::G, C1::G)],
    mut actual: usize,
    blinding_key: &mut (C0::F, C1::F),
    mut Re_0: Re<C0, C1>,
  ) -> Self {
    // While it is possible to use larger values, it's not efficient to do so
    // 2 + 2 == 2^2, yet 2 + 2 + 2 < 2^3
    debug_assert!((RING_LEN == 2) || (RING_LEN == 4));
    debug_assert_eq!(RING_LEN, ring.len());

    let mut s = [(C0::F::zero(), C1::F::zero()); RING_LEN];

    let mut r = (C0::F::random(&mut *rng), C1::F::random(&mut *rng));
    #[allow(non_snake_case)]
    let original_R = (generators.0.alt * r.0, generators.1.alt * r.1);
    #[allow(non_snake_case)]
    let mut R = original_R;

    for i in ((actual + 1) .. (actual + RING_LEN + 1)).map(|i| i % RING_LEN) {
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
      // Generate a decoy response
      } else {
        s[i] = (C0::F::random(&mut *rng), C1::F::random(&mut *rng));
      }

      R = Self::R(generators, s[i], ring[i], e);
    }

    Aos { Re_0, s }
  }

  // Assumes the ring has already been transcripted in some form. Critically insecure if it hasn't
  pub(crate) fn verify<T: Clone + Transcript>(
    &self,
    transcript: T,
    generators: (Generators<C0::G>, Generators<C1::G>),
    batch: &mut (BatchVerifier<(), C0::G>, BatchVerifier<(), C1::G>),
    ring: &[(C0::G, C1::G)],
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
        statements.0.push((C0::F::one(), R0_0));
        statements.1.push((C1::F::one(), R1_0));
        batch.0.queue((), statements.0);
        batch.1.queue((), statements.1);
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
  pub(crate) fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
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
  pub(crate) fn deserialize<R: Read>(r: &mut R, mut Re_0: Re<C0, C1>) -> Result<Self, CurveError> {
    match Re_0 {
      Re::R(ref mut R0, ref mut R1) => {
        *R0 = C0::read_G(r)?;
        *R1 = C1::read_G(r)?
      }
      Re::e(ref mut e) => *e = C0::read_F(r)?,
    }

    let mut s = [(C0::F::zero(), C1::F::zero()); RING_LEN];
    for s in s.iter_mut() {
      *s = (C0::read_F(r)?, C1::read_F(r)?);
    }

    Ok(Aos { Re_0, s })
  }
}
