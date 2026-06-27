#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::ops::Deref as _;
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use std_shims::io;

#[cfg(feature = "alloc")]
use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  },
  GroupIo,
};
use multiexp::multiexp_vartime;
#[cfg(feature = "alloc")]
use multiexp::BatchVerifier;

/// Half-aggregation from <https://eprint.iacr.org/2021/350>.
#[cfg(feature = "aggregate")]
pub mod aggregate;

#[cfg(test)]
mod tests;

/// A Schnorr signature of the form (R, s) where s = r + cx.
///
/// These are intended to be strict. It is generic over `GroupIo` which is for `PrimeGroup`s,
/// and mandates canonical encodings in its read function.
///
/// RFC 8032 has an alternative verification formula for Ed25519, `8R = 8s - 8cX`, which is
/// intended to handle torsioned nonces/public keys. Due to this library's strict requirements,
/// such signatures will not be verifiable with this library.
///
/// This signature is not inherently validated and must be explicitly verified.
#[derive(Clone, Copy, Debug, Zeroize)]
#[expect(non_snake_case)]
pub struct SchnorrSignature<C: GroupIo> {
  /// The nonce commitment.
  pub R: C::G,
  /// The response to the challenge.
  pub s: C::F,
}
impl<C: GroupIo> PartialEq for SchnorrSignature<C> {
  fn eq(&self, other: &Self) -> bool {
    let Self { R, s } = *self;
    (R == other.R) && (s == other.s)
  }
}
impl<C: GroupIo> Eq for SchnorrSignature<C> {}

impl<C: GroupIo> SchnorrSignature<C> {
  /// Read from something implementing [`io::Read`].
  pub fn read(mut reader: impl io::Read) -> io::Result<Self> {
    Ok(SchnorrSignature { R: C::read_G(&mut reader)?, s: C::read_F(&mut reader)? })
  }

  /// Write to something implementing [`io::Write`].
  pub fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    writer.write_all(self.R.to_bytes().as_ref())?;
    writer.write_all(self.s.to_repr().as_ref())
  }

  /// Serialize to a `Vec<u8>`.
  #[cfg(feature = "alloc")]
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = alloc::vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  /// Sign a Schnorr signature with the given nonce for the specified challenge.
  ///
  /// This challenge must be properly crafted, which means being binding to the public key, nonce,
  /// and any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  #[expect(clippy::needless_pass_by_value)] // Prevents further-use of this single-use value
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
  /// This is intended to be used with a multiexp.
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
  #[cfg(feature = "alloc")]
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
