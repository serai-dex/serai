use std::io::{self, Read};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use digest::Digest;

use group::{
  ff::{Field, PrimeField},
  Group,
};

pub use ciphersuite::Ciphersuite;

#[cfg(any(feature = "ristretto", feature = "ed25519"))]
mod dalek;
#[cfg(feature = "ristretto")]
pub use dalek::{Ristretto, IetfRistrettoHram};
#[cfg(feature = "ed25519")]
pub use dalek::{Ed25519, IetfEd25519Hram};

#[cfg(any(feature = "secp256k1", feature = "p256"))]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::{Secp256k1, IetfSecp256k1Hram};
#[cfg(feature = "p256")]
pub use kp256::{P256, IetfP256Hram};

#[cfg(feature = "ed448")]
mod ed448;
#[cfg(feature = "ed448")]
pub use ed448::{Ed448, Ietf8032Ed448Hram, IetfEd448Hram};

/// FROST Ciphersuite, except for the signing algorithm specific H2, making this solely the curve,
/// its associated hash function, and the functions derived from it.
pub trait Curve: Ciphersuite {
  /// Context string for this curve.
  const CONTEXT: &'static [u8];

  /// Hash the given dst and data to a byte vector. Used to instantiate H4 and H5.
  fn hash_to_vec(dst: &[u8], data: &[u8]) -> Vec<u8> {
    Self::H::digest([Self::CONTEXT, dst, data].concat()).as_ref().to_vec()
  }

  /// Field element from hash. Used during key gen and by other crates under Serai as a general
  /// utility. Used to instantiate H1 and H3.
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    <Self as Ciphersuite>::hash_to_F(&[Self::CONTEXT, dst].concat(), msg)
  }

  /// Hash the message for the binding factor. H4 from the IETF draft.
  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    Self::hash_to_vec(b"msg", msg)
  }

  /// Hash the commitments for the binding factor. H5 from the IETF draft.
  fn hash_commitments(commitments: &[u8]) -> Vec<u8> {
    Self::hash_to_vec(b"com", commitments)
  }

  /// Hash the commitments and message to calculate the binding factor. H1 from the IETF draft.
  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    <Self as Curve>::hash_to_F(b"rho", binding)
  }

  /// Securely generate a random nonce. H3 from the IETF draft.
  fn random_nonce<R: RngCore + CryptoRng>(mut secret: Self::F, rng: &mut R) -> Self::F {
    let mut seed = vec![0; 32];
    rng.fill_bytes(&mut seed);

    let mut repr = secret.to_repr();
    secret.zeroize();

    let mut res;
    while {
      seed.extend(repr.as_ref());
      res = <Self as Curve>::hash_to_F(b"nonce", &seed);
      res.ct_eq(&Self::F::zero()).into()
    } {
      rng.fill_bytes(&mut seed);
    }

    for i in repr.as_mut() {
      i.zeroize();
    }
    seed.zeroize();
    res
  }

  #[allow(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let res = <Self as Ciphersuite>::read_G(reader)?;
    if res.is_identity().into() {
      Err(io::Error::new(io::ErrorKind::Other, "identity point"))?;
    }
    Ok(res)
  }
}
