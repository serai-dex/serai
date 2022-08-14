use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use ::curve::ff::PrimeField;
pub use ::curve::CurveError;

#[cfg(any(test, feature = "dalek"))]
mod dalek;
#[cfg(any(test, feature = "ristretto"))]
pub use dalek::IetfRistrettoHram;
#[cfg(feature = "ed25519")]
pub use dalek::IetfEd25519Hram;

#[cfg(feature = "kp256")]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::IetfSecp256k1Hram;
#[cfg(feature = "p256")]
pub use kp256::IetfP256Hram;

/// Unified trait to manage a field/group
// This should be moved into its own crate if the need for generic cryptography over ff/group
// continues, which is the exact reason ff/group exists (to provide a generic interface)
// elliptic-curve exists, yet it doesn't really serve the same role, nor does it use &[u8]/Vec<u8>
// It uses GenericArray which will hopefully be deprecated as Rust evolves and doesn't offer enough
// advantages in the modern day to be worth the hassle -- Kayaba
pub trait Curve: ::curve::Curve {
  /// ID for this curve
  const ID: &'static [u8];

  /// Hash the message for the binding factor. H3 from the IETF draft
  // This doesn't actually need to be part of Curve as it does nothing with the curve
  // This also solely relates to FROST and with a proper Algorithm/HRAM, all projects using
  // aggregatable signatures over this curve will work without issue
  // It is kept here as Curve + H{1, 2, 3, 4} is effectively a ciphersuite according to the IETF
  // draft and moving it to Schnorr would force all of them into being ciphersuite-specific
  // H2 is left to the Schnorr Algorithm as H2 is the H used in HRAM, which Schnorr further
  // modularizes
  fn hash_msg(msg: &[u8]) -> Vec<u8>;

  /// Hash the commitments and message to calculate the binding factor. H1 from the IETF draft
  fn hash_binding_factor(binding: &[u8]) -> Self::F;

  /// Securely generate a random nonce. H4 from the IETF draft
  fn random_nonce<R: RngCore + CryptoRng>(mut secret: Self::F, rng: &mut R) -> Self::F {
    let mut seed = vec![0; 32];
    rng.fill_bytes(&mut seed);

    let mut repr = secret.to_repr();
    secret.zeroize();

    seed.extend(repr.as_ref());
    for i in repr.as_mut() {
      i.zeroize();
    }

    let res = Self::hash_to_F(b"nonce", &seed);
    seed.zeroize();
    res
  }

  /// Field element from hash. Used during key gen and by other crates under Serai as a general
  /// utility
  // Not parameterized by Digest as it's fine for it to use its own hash function as relevant to
  // hash_msg and hash_binding_factor
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;
}
