use std::io;

use sha3::{Digest, Keccak256};

use group::ff::PrimeField;
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
  ProjectivePoint, Scalar, U256 as KU256,
};

use crate::PublicKey;

/// A signature for the Schnorr Solidity library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
  c: Scalar,
  s: Scalar,
}

impl Signature {
  /// Construct a new `Signature`.
  #[must_use]
  pub fn new(c: Scalar, s: Scalar) -> Signature {
    Signature { c, s }
  }

  /// The challenge for a signature.
  #[must_use]
  pub fn challenge(R: ProjectivePoint, key: &PublicKey, message: &[u8]) -> Scalar {
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
    <Scalar as Reduce<KU256>>::reduce_bytes(&hash.finalize())
  }

  /// Verify a signature.
  #[must_use]
  pub fn verify(&self, key: &PublicKey, message: &[u8]) -> bool {
    // Recover the nonce
    let R = (ProjectivePoint::GENERATOR * self.s) - (key.point() * self.c);
    // Check the challenge
    Self::challenge(R, key, message) == self.c
  }

  /// The challenge present within this signature.
  pub fn c(&self) -> Scalar {
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
    res[.. 32].copy_from_slice(self.c.to_repr().as_ref());
    res[32 ..].copy_from_slice(self.s.to_repr().as_ref());
    res
  }

  /// Write the signature.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.to_bytes())
  }

  /// Read a signature.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut read_F = || -> io::Result<Scalar> {
      let mut bytes = [0; 32];
      reader.read_exact(&mut bytes)?;
      Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| io::Error::other("invalid scalar"))
    };
    let c = read_F()?;
    let s = read_F()?;
    Ok(Signature { c, s })
  }

  /// Read a signature from bytes.
  pub fn from_bytes(bytes: [u8; 64]) -> io::Result<Self> {
    Self::read(&mut bytes.as_slice())
  }
}
