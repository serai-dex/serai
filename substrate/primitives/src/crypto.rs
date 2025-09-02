use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

/// A Ristretto public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct Public(pub [u8; 32]);
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct Signature(pub [u8; 64]);
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

/// A key for an external network.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct ExternalKey(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  pub BoundedVec<u8, ConstU32<{ ExternalKey::MAX_LEN }>>,
);

impl AsRef<[u8]> for ExternalKey {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl Zeroize for ExternalKey {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize();
  }
}

impl ExternalKey {
  /// The maximum length for am external key.
  /*
    This support keys up to 96 bytes (such as BLS12-381 G2, which is the largest elliptic-curve
    group element we might reasonably use as a key). This can always be increased if we need to
    adopt a different cryptosystem (one where verification keys are multiple group elements, or
    where group elements do exceed 96 bytes, such as RSA).
  */
  pub const MAX_LEN: u32 = 96;
}

/// Key(s) on embedded elliptic curve(s).
///
/// This may be a single key if the external network uses the same embedded elliptic curve as
/// used for the key to oraclize onto Serai. Else, it'll be a key on the embedded elliptic curve
/// used for the key to oraclize onto Serai concatenated with the key on the embedded elliptic
/// curve used for the external network.
pub type EmbeddedEllipticCurveKeys = BoundedVec<u8, ConstU32<{ 2 * ExternalKey::MAX_LEN }>>;

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for publishing data onto Serai, and their key on the external
/// network.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct KeyPair(pub Public, pub ExternalKey);
