#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;
#[cfg(feature = "serialize")]
use std::io::{self, Read, Write};

use rand_core::{RngCore, CryptoRng};

use curve::{
  group::{ff::Field, Group},
  Curve,
};
#[cfg(feature = "serialize")]
use curve::{
  group::{ff::PrimeField, GroupEncoding},
  CurveError,
};

#[cfg(feature = "batch")]
use multiexp::BatchVerifier;

pub trait Signature<C: Curve>: Sized + Clone + Copy {
  /// Sign a message with the provided nonce.
  fn sign_core(key: C::F, nonce: C::F, msg: &[u8]) -> Self;

  /// Sign a message with a randomly generated nonce.
  fn sign_random_nonce<R: RngCore + CryptoRng>(rng: &mut R, key: C::F, msg: &[u8]) -> Self {
    Self::sign_core(key, C::F::random(rng), msg)
  }

  /*
  For a properly selected hash function (no length extension attacks and so on), this would be
  optimal. sign could then call sign_deterministic_nonce with SHA3. The issues are two-fold:
  1) Needing to perform multiple hashes for the needed bits/use SHAKE256
  2) Needing to convert this to a Scalar for an arbitratry field (only possible with
     double-and-add-style schemes)
  The latter is the main objection at this time.
  */
  /// Sign a message with a deterministic nonce generated as H(x || m).
  // pub fn sign_deterministic_nonce<D: Digest>(key: C::F, msg: &[u8]) -> Self {}

  /// Alias to the preferred sign function, which is currently sign_random_nonce but may change to
  /// a deterministic scheme in the future.
  fn sign<R: RngCore + CryptoRng>(rng: &mut R, key: C::F, msg: &[u8]) -> Self {
    Self::sign_random_nonce(rng, key, msg)
  }

  /// Verify a signature.
  #[must_use]
  fn verify(&self, key: C::G, msg: &[u8]) -> bool;

  /// Serialize a signature.
  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()>;
  /// Deserialize a signature.
  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(reader: &mut R) -> Result<Self, CurveError>;
}

/// A parameterizable HRAm to support a variety of signature specifications.
pub trait Hram<C: Curve>: Sized + Clone + Copy {
  /// HRAM function to generate a challenge
  #[allow(non_snake_case)]
  fn hram(R: C::G, A: C::G, m: &[u8]) -> C::F;
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Schnorr<C: Curve, H: Hram<C>> {
  pub R: C::G,
  pub s: C::F,
  _hram: PhantomData<H>,
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClassicalSchnorr<C: Curve, H: Hram<C>> {
  pub c: C::F,
  pub s: C::F,
  _hram: PhantomData<H>,
}

impl<C: Curve, H: Hram<C>> Schnorr<C, H> {
  #[allow(non_snake_case)]
  pub fn new(R: C::G, s: C::F) -> Self {
    Self { R, s, _hram: PhantomData }
  }

  fn verification_statements(&self, key: C::G, msg: &[u8]) -> [(C::F, C::G); 3] {
    // R + cA == sG where s = r + cx
    [(C::F::one(), self.R), (H::hram(self.R, key, msg), key), (-self.s, C::generator())]
  }

  #[cfg(feature = "batch")]
  pub fn queue_batch_verification<Id: Copy>(
    &self,
    verifier: &mut BatchVerifier<Id, C::G>,
    id: Id,
    key: C::G,
    msg: &[u8],
  ) {
    verifier.queue(id, self.verification_statements(key, msg));
  }
}

impl<C: Curve, H: Hram<C>> Signature<C> for Schnorr<C, H> {
  fn sign_core(key: C::F, nonce: C::F, msg: &[u8]) -> Self {
    #[allow(non_snake_case)]
    let R = C::generator() * nonce;
    Self { R, s: nonce + (key * H::hram(R, C::generator() * key, msg)), _hram: PhantomData }
  }

  /// Verify a signature.
  #[must_use]
  fn verify(&self, key: C::G, msg: &[u8]) -> bool {
    let mut accum = C::G::identity();
    for statement in self.verification_statements(key, msg) {
      accum += statement.1 * statement.0;
    }
    accum.is_identity().into()
  }

  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.R.to_bytes().as_ref())?;
    writer.write_all(self.s.to_repr().as_ref())?;
    Ok(())
  }

  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(reader: &mut R) -> Result<Self, CurveError> {
    Ok(Self::new(C::read_G(reader)?, C::read_F(reader)?))
  }
}

impl<C: Curve, H: Hram<C>> ClassicalSchnorr<C, H> {
  pub fn new(c: C::F, s: C::F) -> Self {
    Self { c, s, _hram: PhantomData }
  }
}

impl<C: Curve, H: Hram<C>> Signature<C> for ClassicalSchnorr<C, H> {
  fn sign_core(key: C::F, nonce: C::F, msg: &[u8]) -> Self {
    let c = H::hram(C::generator() * nonce, C::generator() * key, msg);
    Self { c, s: nonce - (key * c), _hram: PhantomData }
  }

  /// Verify a signature.
  #[must_use]
  fn verify(&self, key: C::G, msg: &[u8]) -> bool {
    self.c == H::hram((C::generator() * self.s) + (key * self.c), key, msg)
  }

  #[cfg(feature = "serialize")]
  fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.c.to_repr().as_ref())?;
    writer.write_all(self.s.to_repr().as_ref())?;
    Ok(())
  }

  #[cfg(feature = "serialize")]
  fn deserialize<R: Read>(reader: &mut R) -> Result<Self, CurveError> {
    Ok(Self::new(C::read_F(reader)?, C::read_F(reader)?))
  }
}
