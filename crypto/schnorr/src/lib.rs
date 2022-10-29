use std::io::{self, Read, Write};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

use multiexp::BatchVerifier;

use ciphersuite::Ciphersuite;

#[cfg(test)]
mod tests;

/// A Schnorr signature of the form (R, s) where s = r + cx.
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct SchnorrSignature<C: Ciphersuite> {
  pub R: C::G,
  pub s: C::F,
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

  /// Serialize a SchnorrSignature, returning a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  /// Sign a Schnorr signature with the given nonce for the specified challenge.
  pub fn sign(mut private_key: C::F, mut nonce: C::F, challenge: C::F) -> SchnorrSignature<C> {
    let res = SchnorrSignature { R: C::generator() * nonce, s: nonce + (private_key * challenge) };
    private_key.zeroize();
    nonce.zeroize();
    res
  }

  /// Verify a Schnorr signature for the given key with the specified challenge.
  #[must_use]
  pub fn verify(&self, public_key: C::G, challenge: C::F) -> bool {
    (C::generator() * self.s) == (self.R + (public_key * challenge))
  }

  /// Queue a signature for batch verification.
  pub fn batch_verify<R: RngCore + CryptoRng, I: Copy + Zeroize>(
    &self,
    rng: &mut R,
    batch: &mut BatchVerifier<I, C::G>,
    id: I,
    public_key: C::G,
    challenge: C::F,
  ) {
    // s = r + ca
    // sG == R + cA
    // R + cA - sG == 0

    batch.queue(
      rng,
      id,
      [
        // R
        (C::F::one(), self.R),
        // cA
        (challenge, public_key),
        // -sG
        (-self.s, C::generator()),
      ],
    );
  }
}
