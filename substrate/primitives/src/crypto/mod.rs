use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

mod external_key;
pub use external_key::*;
mod embedded_elliptic_curve_keys;
pub use embedded_elliptic_curve_keys::*;

/// A Ristretto public key.
///
/// This is approximate to [`sp_core::sr25519::Public`] but implements the APIs from `borsh`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Public(pub [u8; 32]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Public);
impl From<sp_core::sr25519::Public> for Public {
  fn from(public: sp_core::sr25519::Public) -> Self {
    Self(public.0)
  }
}
impl From<Public> for sp_core::sr25519::Public {
  fn from(public: Public) -> Self {
    Self::from_raw(public.0)
  }
}

/// A sr25519 signature.
///
/// This is approximate to [`sp_core::sr25519::Signature`] but implements the APIs from `borsh`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct Signature(pub [u8; 64]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Signature);
impl From<schnorrkel::Signature> for Signature {
  fn from(signature: schnorrkel::Signature) -> Self {
    Self(signature.to_bytes())
  }
}
impl From<sp_core::sr25519::Signature> for Signature {
  fn from(signature: sp_core::sr25519::Signature) -> Self {
    Self(signature.0)
  }
}
impl From<Signature> for sp_core::sr25519::Signature {
  fn from(signature: Signature) -> Self {
    Self::from_raw(signature.0)
  }
}

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for publishing data onto Serai, and their key on the external
/// network.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct KeyPair(pub Public, pub ExternalKey);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(KeyPair);
