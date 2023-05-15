#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref;
#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
  },
  Ciphersuite,
};
use multiexp::{multiexp_vartime, BatchVerifier};

/// Half-aggregation from <https://eprint.iacr.org/2021/350>.
pub mod aggregate;

#[cfg(test)]
mod tests;

/// A Schnorr signature of the form (R, s) where s = r + cx.
///
/// These are intended to be strict. It is generic over Ciphersuite which is for PrimeGroups,
/// and mandates canonical encodings in its read function.
///
/// RFC 8032 has an alternative verification formula, 8R = 8s - 8cX, which is intended to handle
/// torsioned nonces/public keys. Due to this library's strict requirements, such signatures will
/// not be verifiable with this library.
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct SchnorrSignature<C: Ciphersuite> {
  pub R: C::G,
  pub s: C::F,
}

impl<C: Ciphersuite> Default for SchnorrSignature<C> {
  fn default() -> Self {
    SchnorrSignature { R: C::generator(), s: C::F::ZERO }
  }
}

impl<C: Ciphersuite> SchnorrSignature<C> {
  /// Read a SchnorrSignature from something implementing Read.
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    Ok(SchnorrSignature { R: C::read_G(reader)?, s: C::read_F(reader)? })
  }

  /// Write a SchnorrSignature to something implementing Read.
  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.R.to_bytes().as_ref())?;
    writer.write_all(self.s.to_repr().as_ref())
  }

  /// Serialize a SchnorrSignature, returning a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  /// Sign a Schnorr signature with the given nonce for the specified challenge.
  ///
  /// This challenge must be properly crafted, which means being binding to the public key, nonce,
  /// and any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  pub fn sign(
    private_key: &Zeroizing<C::F>,
    nonce: Zeroizing<C::F>,
    challenge: C::F,
  ) -> SchnorrSignature<C> {
    SchnorrSignature {
      // Uses deref instead of * as * returns C::F yet deref returns &C::F, preventing a copy
      R: C::generator() * nonce.deref(),
      s: (challenge * private_key.deref()) + nonce.deref(),
    }
  }

  /// Return the series of pairs whose products sum to zero for a valid signature.
  /// This is inteded to be used with a multiexp.
  pub fn batch_statements(&self, public_key: C::G, challenge: C::F) -> [(C::F, C::G); 3] {
    // s = r + ca
    // sG == R + cA
    // R + cA - sG == 0
    [
      // R
      (C::F::ONE, self.R),
      // cA
      (challenge, public_key),
      // -sG
      (-self.s, C::generator()),
    ]
  }

  /// Verify a Schnorr signature for the given key with the specified challenge.
  ///
  /// This challenge must be properly crafted, which means being binding to the public key, nonce,
  /// and any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  #[must_use]
  pub fn verify(&self, public_key: C::G, challenge: C::F) -> bool {
    multiexp_vartime(&self.batch_statements(public_key, challenge)).is_identity().into()
  }

  /// Queue a signature for batch verification.
  ///
  /// This challenge must be properly crafted, which means being binding to the public key, nonce,
  /// and any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  pub fn batch_verify<R: RngCore + CryptoRng, I: Copy + Zeroize>(
    &self,
    rng: &mut R,
    batch: &mut BatchVerifier<I, C::G>,
    id: I,
    public_key: C::G,
    challenge: C::F,
  ) {
    batch.queue(rng, id, self.batch_statements(public_key, challenge));
  }
}
