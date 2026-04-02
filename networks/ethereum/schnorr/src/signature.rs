use std_shims::io;

use sha3::{Digest as _, Keccak256};

use group::ff::PrimeField as _;
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint as _},
  ProjectivePoint, Scalar, U256 as KU256,
};

use crate::PublicKey;

/// A signature for the Schnorr Solidity library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
  c: [u8; 32],
  s: Scalar,
}

impl Signature {
  fn c_scalar(&self) -> Scalar {
    <Scalar as Reduce<KU256>>::reduce_bytes(&self.c.into())
  }

  /// Construct a new `Signature`.
  #[must_use]
  pub fn new(c: [u8; 32], s: Scalar) -> Option<Signature> {
    let signature = Signature { c, s };
    if bool::from(signature.c_scalar().is_zero()) {
      None?;
    }
    Some(signature)
  }

  /// The challenge for a signature.
  ///
  /// This returns a `[u8; 32]` as the Schnorr verifier contract considers the challenge a hash,
  /// not a hash reduced into a scalar. Given the order of secp256k1, these values will be
  /// equivalent except with negligible probability, but this is still the technically correct
  /// representation.
  ///
  /// With negligible probability, this MAY return a value congruent to `0` modulo the order of
  /// secp256k1, which will create an invalid/unverifiable signature.
  #[must_use]
  pub fn challenge(R: ProjectivePoint, key: &PublicKey, message: &[u8]) -> [u8; 32] {
    // H(R || A || m)
    let mut hash = Keccak256::new();
    // We transcript the nonce as an address since ecrecover yields an address
    hash.update({
      let uncompressed_encoded_point = R.to_encoded_point(false);
      // Skip the prefix byte marking this as uncompressed
      let x_and_y_coordinates = &uncompressed_encoded_point.as_ref()[1 ..];
      // Last 20 bytes of the hash of the x and y coordinates
      &Keccak256::digest(x_and_y_coordinates)[12 ..]
    });
    hash.update(key.eth_repr());
    hash.update(Keccak256::digest(message));
    hash.finalize().into()
  }

  /// Verify a signature.
  #[must_use]
  pub fn verify(&self, key: &PublicKey, message: &[u8]) -> bool {
    // Recover the nonce
    let R = (ProjectivePoint::GENERATOR * self.s) - (key.point() * self.c_scalar());
    // Check the challenge
    Self::challenge(R, key, message) == self.c
  }

  /// The challenge present within this signature.
  pub fn c(&self) -> [u8; 32] {
    self.c
  }

  /// The signature solution present within this signature.
  pub fn s(&self) -> Scalar {
    self.s
  }

  /// Convert the signature to bytes.
  #[must_use]
  pub fn to_bytes(&self) -> [u8; 64] {
    let mut res = [0; 64];
    res[.. 32].copy_from_slice(&self.c);
    res[32 ..].copy_from_slice(self.s.to_repr().as_ref());
    res
  }

  /// Write the signature.
  #[cfg(feature = "alloc")]
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.to_bytes())
  }

  /// Read a signature.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut c = [0; 32];
    reader.read_exact(&mut c)?;
    let c = c;

    let mut s = [0; 32];
    reader.read_exact(&mut s)?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s.into()))
      .ok_or_else(|| io::Error::other("invalid scalar"))?;

    Ok(Signature { c, s })
  }

  /// Read a signature from bytes.
  pub fn from_bytes(bytes: [u8; 64]) -> io::Result<Self> {
    Self::read(&mut bytes.as_slice())
  }
}
