use core::{ops::Deref as _, convert::AsRef};
use std_shims::{
  prelude::*,
  io::{self, Read},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize as _, Zeroizing};
use subtle::ConstantTimeEq as _;

use ciphersuite::group::{
  ff::{Field as _, PrimeField as _},
  Group as _,
};
pub use ciphersuite::{digest::Digest, WrappedGroup, GroupIo, Ciphersuite};

#[cfg(any(feature = "ristretto", feature = "ed25519"))]
mod dalek;
#[cfg(any(feature = "ristretto", feature = "ed25519"))]
pub use dalek::*;

#[cfg(any(feature = "secp256k1", feature = "p256"))]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::{Secp256k1, IrtfSecp256k1Hram};
#[cfg(feature = "p256")]
pub use kp256::{P256, IrtfP256Hram};

#[cfg(feature = "ed448")]
mod ed448;
#[cfg(feature = "ed448")]
pub use ed448::{Ed448, IrtfEd448Hram};
#[cfg(all(test, feature = "ed448"))]
pub(crate) use ed448::Irtf8032Ed448Hram;

/// FROST Ciphersuite.
///
/// This excludes the signing algorithm specific H2, making this solely the curve, its associated
/// hash function, and the functions derived from it.
pub trait Curve: GroupIo + Ciphersuite {
  /// Context string for this curve.
  const CONTEXT: &[u8];

  /// Hash the specified `dst` and `data` to a byte vector.
  ///
  /// This is used to instantiate H4 and H5 and has no safety/correctness guarantees other than for
  /// that purpose.
  fn hash(dst: &[u8], data: &[u8]) -> impl AsRef<[u8]> {
    Self::H::digest([Self::CONTEXT, dst, data].concat())
  }

  /// Derive a scalar field element from the digest of the hash function.
  ///
  /// This is used to instantiate H1 and H3 and has no safety/correctness guarantees other than for
  /// that purpose.
  ///
  /// The `dst` MUST be prefixed by `Self::CONTEXT` by the implementor.
  #[expect(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;

  /// Hash the message for the binding factor.
  ///
  /// This corresponds to H4 from the IRTF standard.
  fn hash_msg(msg: &[u8]) -> impl AsRef<[u8]> {
    Self::hash(b"msg", msg)
  }

  /// Hash the commitments for the binding factor.
  ///
  /// This corresponds to H5 from the IRTF standard.
  fn hash_commitments(commitments: &[u8]) -> impl AsRef<[u8]> {
    Self::hash(b"com", commitments)
  }

  /// Hash the commitments and message to calculate the binding factor.
  ///
  /// This corresponds to H1 from the IRTF standard.
  //
  // This may return 0, which is invalid according to the FROST preprint, as all binding factors
  // are expected to be in the multiplicative subgroup. This isn't a practical issue, as there's a
  // negligible probability of this returning 0.
  //
  // When raised in
  // https://github.com/cfrg/draft-irtf-cfrg-frost/issues/451#issuecomment-1715985505,
  // the negligible probbility was seen as sufficient reason not to edit the spec to be robust in
  // this regard.
  //
  // While that decision may be disagreeable, this library cannot implement a robust scheme while
  // following the specification. Following the specification is preferred to being robust against
  // an impractical probability enabling a complex attack (made infeasible by the impractical
  // probability required).
  //
  // We could still panic on the 0-hash, preferring correctness to liveliness. Finding the 0-hash
  // is as computationally complex as simply calculating the group key's discrete log however,
  // making it not worth having a panic (as this library is expected not to panic).
  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    <Self as Curve>::hash_to_F(b"rho", binding)
  }

  /// Securely generate a random nonce.
  ///
  /// This corresponds to H3 from the IRTF standard.
  fn random_nonce<R: RngCore + CryptoRng>(
    secret: &Zeroizing<Self::F>,
    rng: &mut R,
  ) -> Zeroizing<Self::F> {
    let mut seed = Zeroizing::new(vec![0; 32]);
    rng.fill_bytes(seed.as_mut());

    let mut repr = secret.to_repr();

    /*
      Perform rejection sampling until we reach a non-zero nonce

      While the IRTF spec doesn't explicitly require this, generating a zero nonce will produce
      commitments which will be rejected for being zero (and if they were used, leak the secret
      share). Rejection sampling here will prevent an honest participant from ever generating
      'malicious' values and ensure safety.
    */
    let mut res;
    while {
      seed.extend(repr.as_ref());
      res = Zeroizing::new(<Self as Curve>::hash_to_F(b"nonce", seed.deref()));
      res.ct_eq(&Self::F::ZERO).into()
    } {
      seed = Zeroizing::new(vec![0; 32]);
      rng.fill_bytes(&mut seed);
    }
    repr.as_mut().zeroize();

    res
  }

  /// Read a point from a reader, rejecting identity.
  #[expect(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let res = <Self as GroupIo>::read_G(reader)?;
    if res.is_identity().into() {
      Err(io::Error::other("identity point"))?;
    }
    Ok(res)
  }
}
